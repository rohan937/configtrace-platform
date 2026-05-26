"""Tests for M58.8 — Incident-Style Change Rooms: Investigation Notes.

Test strategy
-------------
Pure unit tests using MagicMock for database sessions and the FastAPI
TestClient for router endpoints.  No real DB connection required.
DATABASE_URL=sqlite:///test.db is fine.

Coverage
--------
Model (TestChangeNoteModel):
  1.  Model imports cleanly and has correct table name
  2.  Model has expected columns
  3.  ChangeNote repr includes change_id and body preview

Migration (TestChangeNoteMigration):
  4.  Migration imports and has correct revision chain (mig012 → mig011)
  5.  Migration creates change_notes table on upgrade
  6.  Migration drops change_notes table on downgrade

Schema (TestChangeNoteSchema):
  7.  ChangeNoteCreate accepts valid body
  8.  ChangeNoteCreate strips leading/trailing whitespace
  9.  ChangeNoteCreate rejects empty body
  10. ChangeNoteCreate rejects whitespace-only body
  11. ChangeNoteCreate rejects body exceeding 2000 characters
  12. ChangeNoteResponse round-trips via from_attributes

Service (TestChangeNoteService):
  13. list_notes queries DB filtered by change_id, ordered by created_at
  14. list_notes returns empty list when no notes exist
  15. create_note adds a ChangeNote row and commits
  16. create_note persists workspace_id and author_user_id
  17. create_note strips whitespace before storing
  18. create_note raises ValueError on empty body (defence in depth)
  19. create_note raises ValueError on body > 2000 chars (defence in depth)

Router (TestChangeNoteRouter):
  20. GET /changes/{id}/notes — returns 200 with empty list when no notes
  21. GET /changes/{id}/notes — returns list of notes with total count
  22. POST /changes/{id}/notes — returns 201 with created note
  23. POST /changes/{id}/notes — note body is returned as plain text (no interpretation)
  24. POST /changes/{id}/notes — empty body returns 422
  25. POST /changes/{id}/notes — body exceeding 2000 chars returns 422
  26. GET /changes/{id}/notes — non-member gets 404 (cross-workspace auth)
  27. POST /changes/{id}/notes — non-member gets 404 (cross-workspace auth)
  28. Existing review actions (acknowledge) still return 200 unaffected
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_mock_db() -> MagicMock:
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.query.return_value.filter.return_value.order_by.return_value.all.return_value = []
    db.get.return_value = None
    return db


def _make_mock_note(change_id=None, workspace_id=None, author_user_id=None, body="Test note."):
    note = MagicMock()
    note.id = uuid.uuid4()
    note.change_id = change_id or uuid.uuid4()
    note.workspace_id = workspace_id or uuid.uuid4()
    note.author_user_id = author_user_id or uuid.uuid4()
    note.body = body
    note.created_at = _utcnow()
    note.updated_at = _utcnow()
    return note


def _make_mock_change(user_id=None):
    change = MagicMock()
    change.id = uuid.uuid4()
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


def _make_mock_user(user_id=None):
    user = MagicMock()
    user.id = user_id or uuid.uuid4()
    user.email = "investigator@example.com"
    return user


# ── 1–3: Model ────────────────────────────────────────────────────────────────


class TestChangeNoteModel:
    def test_model_imports(self):
        from app.models.change_note import ChangeNote
        assert ChangeNote is not None

    def test_table_name(self):
        from app.models.change_note import ChangeNote
        assert ChangeNote.__tablename__ == "change_notes"

    def test_model_has_expected_columns(self):
        from app.models.change_note import ChangeNote
        cols = {c.key for c in ChangeNote.__table__.columns}
        assert "id" in cols
        assert "change_id" in cols
        assert "workspace_id" in cols
        assert "author_user_id" in cols
        assert "body" in cols
        assert "created_at" in cols
        assert "updated_at" in cols

    def test_repr_includes_change_id(self):
        from app.models.change_note import ChangeNote
        row = MagicMock(spec=ChangeNote)
        row.change_id = uuid.uuid4()
        row.author_user_id = uuid.uuid4()
        row.body = "Investigation underway."
        r = ChangeNote.__repr__(row)
        assert str(row.change_id) in r

    def test_repr_includes_body_preview(self):
        from app.models.change_note import ChangeNote
        row = MagicMock(spec=ChangeNote)
        row.change_id = uuid.uuid4()
        row.author_user_id = None
        row.body = "First 40 chars visible" + "x" * 100
        r = ChangeNote.__repr__(row)
        assert "First 40 chars visible" in r


# ── 4–6: Migration ────────────────────────────────────────────────────────────


def _load_migration_012():
    """Load the migration file via spec_from_file_location (no package needed)."""
    import importlib.util
    import os
    versions_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "alembic", "versions")
    )
    spec = importlib.util.spec_from_file_location(
        "migration_012",
        os.path.join(versions_dir, "012_m588_change_notes.py"),
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class TestChangeNoteMigration:
    def test_migration_imports(self):
        m = _load_migration_012()
        assert m.revision == "mig012"
        assert m.down_revision == "mig011"

    def test_migration_revision_chain(self):
        m = _load_migration_012()
        # Must come after mig011 (push subscriptions)
        assert m.down_revision == "mig011"

    def test_upgrade_creates_table(self):
        m = _load_migration_012()
        with patch("alembic.op.create_table") as mock_ct, \
             patch("alembic.op.create_index"):
            m.upgrade()
        mock_ct.assert_called_once()
        table_name = mock_ct.call_args[0][0]
        assert table_name == "change_notes"

    def test_upgrade_creates_indexes(self):
        m = _load_migration_012()
        with patch("alembic.op.create_table"), \
             patch("alembic.op.create_index") as mock_ci:
            m.upgrade()
        created = {c[0][0] for c in mock_ci.call_args_list}
        assert "ix_change_notes_change_id" in created
        assert "ix_change_notes_workspace_id" in created

    def test_downgrade_drops_table(self):
        m = _load_migration_012()
        with patch("alembic.op.drop_index"), \
             patch("alembic.op.drop_table") as mock_dt:
            m.downgrade()
        mock_dt.assert_called_once_with("change_notes")


# ── 7–12: Schema ──────────────────────────────────────────────────────────────


class TestChangeNoteSchema:
    def test_create_accepts_valid_body(self):
        from app.schemas.change_note import ChangeNoteCreate
        req = ChangeNoteCreate(body="Checked the deployment log. Looks expected.")
        assert req.body == "Checked the deployment log. Looks expected."

    def test_create_strips_whitespace(self):
        from app.schemas.change_note import ChangeNoteCreate
        req = ChangeNoteCreate(body="  hello  ")
        assert req.body == "hello"

    def test_create_rejects_empty_body(self):
        import pydantic
        from app.schemas.change_note import ChangeNoteCreate
        with pytest.raises(pydantic.ValidationError, match="empty"):
            ChangeNoteCreate(body="")

    def test_create_rejects_whitespace_only_body(self):
        import pydantic
        from app.schemas.change_note import ChangeNoteCreate
        with pytest.raises(pydantic.ValidationError, match="empty"):
            ChangeNoteCreate(body="   \t\n  ")

    def test_create_rejects_body_too_long(self):
        import pydantic
        from app.schemas.change_note import ChangeNoteCreate
        with pytest.raises(pydantic.ValidationError, match="2000"):
            ChangeNoteCreate(body="x" * 2001)

    def test_create_accepts_exactly_2000_chars(self):
        from app.schemas.change_note import ChangeNoteCreate
        req = ChangeNoteCreate(body="a" * 2000)
        assert len(req.body) == 2000

    def test_response_round_trips_from_attributes(self):
        from app.schemas.change_note import ChangeNoteResponse
        note = _make_mock_note()
        resp = ChangeNoteResponse.model_validate(note)
        assert resp.body == note.body
        assert resp.change_id == note.change_id
        assert resp.author_user_id == note.author_user_id

    def test_list_response_has_items_and_total(self):
        from app.schemas.change_note import ChangeNoteListResponse, ChangeNoteResponse
        note = _make_mock_note()
        resp_item = ChangeNoteResponse.model_validate(note)
        list_resp = ChangeNoteListResponse(items=[resp_item], total=1)
        assert list_resp.total == 1
        assert len(list_resp.items) == 1


# ── 13–19: Service ────────────────────────────────────────────────────────────


class TestChangeNoteService:
    def test_list_notes_queries_by_change_id(self):
        from app.services.change_note_service import list_notes
        db = _make_mock_db()
        change_id = uuid.uuid4()
        list_notes(change_id=change_id, db=db)
        db.query.assert_called_once()

    def test_list_notes_returns_empty_list(self):
        from app.services.change_note_service import list_notes
        db = _make_mock_db()
        result = list_notes(change_id=uuid.uuid4(), db=db)
        assert result == []

    def test_list_notes_returns_results(self):
        from app.services.change_note_service import list_notes
        db = _make_mock_db()
        change_id = uuid.uuid4()
        notes = [_make_mock_note(change_id=change_id) for _ in range(3)]
        db.query.return_value.filter.return_value.order_by.return_value.all.return_value = notes
        result = list_notes(change_id=change_id, db=db)
        assert result == notes

    def test_create_note_calls_db_add_and_commit(self):
        from app.services.change_note_service import create_note
        db = _make_mock_db()
        change_id = uuid.uuid4()
        workspace_id = uuid.uuid4()
        author_id = uuid.uuid4()

        mock_note = _make_mock_note(change_id=change_id, body="Seems like a planned deploy.")
        db.refresh.side_effect = lambda n: None

        with patch("app.services.change_note_service.ChangeNote", return_value=mock_note):
            create_note(
                change_id=change_id,
                workspace_id=workspace_id,
                author_user_id=author_id,
                body="Seems like a planned deploy.",
                db=db,
            )
        db.add.assert_called_once_with(mock_note)
        db.commit.assert_called_once()

    def test_create_note_persists_workspace_and_author(self):
        from app.services.change_note_service import create_note
        db = _make_mock_db()
        change_id = uuid.uuid4()
        workspace_id = uuid.uuid4()
        author_id = uuid.uuid4()

        captured = {}

        def _capture_note(**kwargs):
            captured.update(kwargs)
            note = _make_mock_note(change_id=change_id, body=kwargs.get("body", ""))
            note.workspace_id = kwargs.get("workspace_id")
            note.author_user_id = kwargs.get("author_user_id")
            return note

        with patch("app.services.change_note_service.ChangeNote", side_effect=_capture_note):
            create_note(
                change_id=change_id,
                workspace_id=workspace_id,
                author_user_id=author_id,
                body="Confirm deployment.",
                db=db,
            )

        assert captured.get("workspace_id") == workspace_id
        assert captured.get("author_user_id") == author_id

    def test_create_note_strips_whitespace_before_storing(self):
        from app.services.change_note_service import create_note
        db = _make_mock_db()
        captured = {}

        def _capture(**kwargs):
            captured.update(kwargs)
            return _make_mock_note(body=kwargs.get("body", ""))

        with patch("app.services.change_note_service.ChangeNote", side_effect=_capture):
            create_note(
                change_id=uuid.uuid4(),
                workspace_id=uuid.uuid4(),
                author_user_id=uuid.uuid4(),
                body="  padded note  ",
                db=db,
            )

        assert captured.get("body") == "padded note"

    def test_create_note_raises_on_empty_body(self):
        from app.services.change_note_service import create_note
        db = _make_mock_db()
        with pytest.raises(ValueError, match="empty"):
            create_note(
                change_id=uuid.uuid4(),
                workspace_id=uuid.uuid4(),
                author_user_id=uuid.uuid4(),
                body="   ",
                db=db,
            )

    def test_create_note_raises_on_body_too_long(self):
        from app.services.change_note_service import create_note
        db = _make_mock_db()
        with pytest.raises(ValueError, match="2000"):
            create_note(
                change_id=uuid.uuid4(),
                workspace_id=uuid.uuid4(),
                author_user_id=uuid.uuid4(),
                body="x" * 2001,
                db=db,
            )


# ── 20–28: Router ─────────────────────────────────────────────────────────────


def _make_app():
    from fastapi import FastAPI
    from app.routers.changes import router
    _app = FastAPI()
    _app.include_router(router)
    return _app


class TestChangeNoteRouter:
    def test_get_notes_empty_list(self):
        """GET /changes/{id}/notes returns 200 with empty items list."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = _make_app()
        user = _make_mock_user()
        change = _make_mock_change(user_id=user.id)
        ws_id = uuid.uuid4()

        mock_db = _make_mock_db()

        with patch("app.routers.changes._get_change_and_workspace",
                   return_value=(change, ws_id)), \
             patch("app.services.change_note_service.list_notes", return_value=[]):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db
            client = TestClient(app)
            resp = client.get(f"/changes/{change.id}/notes")

        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["total"] == 0

    def test_get_notes_returns_list(self):
        """GET /changes/{id}/notes returns notes with correct total."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = _make_app()
        user = _make_mock_user()
        change = _make_mock_change(user_id=user.id)
        ws_id = uuid.uuid4()

        notes = [
            _make_mock_note(change_id=change.id, body="First note."),
            _make_mock_note(change_id=change.id, body="Second note."),
        ]
        mock_db = _make_mock_db()

        with patch("app.routers.changes._get_change_and_workspace",
                   return_value=(change, ws_id)), \
             patch("app.services.change_note_service.list_notes", return_value=notes):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db
            client = TestClient(app)
            resp = client.get(f"/changes/{change.id}/notes")

        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert len(body["items"]) == 2
        assert body["items"][0]["body"] == "First note."

    def test_post_note_returns_201(self):
        """POST /changes/{id}/notes returns 201 with created note."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = _make_app()
        user = _make_mock_user()
        change = _make_mock_change(user_id=user.id)
        ws_id = uuid.uuid4()

        created_note = _make_mock_note(
            change_id=change.id,
            workspace_id=ws_id,
            author_user_id=user.id,
            body="Deployment confirmed via ticket #1234.",
        )
        mock_db = _make_mock_db()

        with patch("app.routers.changes._get_change_and_workspace",
                   return_value=(change, ws_id)), \
             patch("app.services.change_note_service.create_note", return_value=created_note):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db
            client = TestClient(app)
            resp = client.post(
                f"/changes/{change.id}/notes",
                json={"body": "Deployment confirmed via ticket #1234."},
            )

        assert resp.status_code == 201
        body = resp.json()
        assert body["body"] == "Deployment confirmed via ticket #1234."

    def test_post_note_body_returned_as_plain_text(self):
        """Note body containing HTML/script tags is stored and returned as-is (plain text)."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = _make_app()
        user = _make_mock_user()
        change = _make_mock_change(user_id=user.id)
        ws_id = uuid.uuid4()

        raw_body = "<script>alert('xss')</script> This is a note."
        created_note = _make_mock_note(
            change_id=change.id,
            body=raw_body,
        )
        mock_db = _make_mock_db()

        with patch("app.routers.changes._get_change_and_workspace",
                   return_value=(change, ws_id)), \
             patch("app.services.change_note_service.create_note", return_value=created_note):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db
            client = TestClient(app)
            resp = client.post(
                f"/changes/{change.id}/notes",
                json={"body": raw_body},
            )

        assert resp.status_code == 201
        # Body returned unchanged — server does not sanitise or interpret HTML
        assert resp.json()["body"] == raw_body

    def test_post_note_empty_body_returns_422(self):
        """POST /changes/{id}/notes with empty body returns 422."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = _make_app()
        user = _make_mock_user()
        change = _make_mock_change(user_id=user.id)
        ws_id = uuid.uuid4()
        mock_db = _make_mock_db()

        with patch("app.routers.changes._get_change_and_workspace",
                   return_value=(change, ws_id)):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db
            client = TestClient(app)
            resp = client.post(
                f"/changes/{change.id}/notes",
                json={"body": ""},
            )

        assert resp.status_code == 422

    def test_post_note_whitespace_only_returns_422(self):
        """POST /changes/{id}/notes with whitespace-only body returns 422."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = _make_app()
        user = _make_mock_user()
        change = _make_mock_change(user_id=user.id)
        ws_id = uuid.uuid4()
        mock_db = _make_mock_db()

        with patch("app.routers.changes._get_change_and_workspace",
                   return_value=(change, ws_id)):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db
            client = TestClient(app)
            resp = client.post(
                f"/changes/{change.id}/notes",
                json={"body": "   "},
            )

        assert resp.status_code == 422

    def test_post_note_body_too_long_returns_422(self):
        """POST /changes/{id}/notes with body > 2000 chars returns 422."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = _make_app()
        user = _make_mock_user()
        change = _make_mock_change(user_id=user.id)
        ws_id = uuid.uuid4()
        mock_db = _make_mock_db()

        with patch("app.routers.changes._get_change_and_workspace",
                   return_value=(change, ws_id)):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db
            client = TestClient(app)
            resp = client.post(
                f"/changes/{change.id}/notes",
                json={"body": "x" * 2001},
            )

        assert resp.status_code == 422

    def test_get_notes_nonmember_gets_404(self):
        """GET /changes/{id}/notes raises 404 for non-workspace-members (cross-workspace auth)."""
        from fastapi import HTTPException
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = _make_app()
        user = _make_mock_user()
        change = _make_mock_change()  # different user_id
        mock_db = _make_mock_db()

        def _raise_404(*args, **kwargs):
            raise HTTPException(status_code=404, detail="Change not found.")

        with patch("app.routers.changes._get_change_and_workspace", side_effect=_raise_404):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db
            client = TestClient(app)
            resp = client.get(f"/changes/{change.id}/notes")

        assert resp.status_code == 404

    def test_post_notes_nonmember_gets_404(self):
        """POST /changes/{id}/notes raises 404 for non-workspace-members."""
        from fastapi import HTTPException
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = _make_app()
        user = _make_mock_user()
        change = _make_mock_change()
        mock_db = _make_mock_db()

        def _raise_404(*args, **kwargs):
            raise HTTPException(status_code=404, detail="Change not found.")

        with patch("app.routers.changes._get_change_and_workspace", side_effect=_raise_404):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db
            client = TestClient(app)
            resp = client.post(
                f"/changes/{change.id}/notes",
                json={"body": "attempting cross-workspace note"},
            )

        assert resp.status_code == 404

    def test_existing_acknowledge_action_unaffected(self):
        """Existing POST /changes/{id}/acknowledge still returns 200 after notes addition."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = _make_app()
        user = _make_mock_user()
        change = _make_mock_change(user_id=user.id)
        ws_id = uuid.uuid4()

        mock_review = MagicMock()
        mock_review.change_id = change.id
        mock_review.review_status = "acknowledged"
        mock_review.reviewed_by_user_id = user.id
        mock_review.reviewed_at = _utcnow()
        mock_review.review_note = "Deployment confirmed."
        mock_review.snoozed_until = None
        mock_review.snooze_reason = None
        mock_db = _make_mock_db()

        with patch("app.routers.changes._get_change_and_workspace",
                   return_value=(change, ws_id)), \
             patch("app.services.change_review_service.acknowledge_change",
                   return_value=mock_review):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db
            client = TestClient(app)
            resp = client.post(
                f"/changes/{change.id}/acknowledge",
                json={"note": "Deployment confirmed."},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["review_status"] == "acknowledged"
