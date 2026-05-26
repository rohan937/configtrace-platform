"""M58.16: Expected Change Windows — unit tests.

Tests cover the service layer (CRUD + match logic) directly.
No HTTP layer or external dependencies required.

Run:
    cd backend && python -m pytest tests/test_milestone58_16.py -v

All 17 tests must pass.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.schemas.expected_change_window import ExpectedChangeWindowCreate
from app.services import expected_change_service


# ── Helpers ───────────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _window_create(
    title: str = "Deploy v2.1",
    hours_from_now: float = 1.0,
    duration_hours: float = 4.0,
    alert_behavior: str = "annotate_only",
    filter_provider: str | None = None,
    filter_integration_id: uuid.UUID | None = None,
    filter_risk_level: str | None = None,
) -> ExpectedChangeWindowCreate:
    """Build a valid ExpectedChangeWindowCreate request."""
    now = _utcnow()
    start = now + timedelta(hours=hours_from_now)
    end = start + timedelta(hours=duration_hours)
    return ExpectedChangeWindowCreate(
        title=title,
        start_time=start,
        end_time=end,
        alert_behavior=alert_behavior,
        filter_provider=filter_provider,
        filter_integration_id=filter_integration_id,
        filter_risk_level=filter_risk_level,
    )


def _mock_db():
    """Return a minimal MagicMock session."""
    db = MagicMock()
    db.add = MagicMock()
    db.flush = MagicMock()
    return db


def _make_window(
    *,
    workspace_id: uuid.UUID,
    status: str = "pending",
    start_offset_hours: float = -1.0,
    end_offset_hours: float = 3.0,
    filter_provider: str | None = None,
    filter_integration_id: uuid.UUID | None = None,
    filter_risk_level: str | None = None,
    alert_behavior: str = "annotate_only",
    approved_at: datetime | None = None,
):
    """Build a MagicMock representing an ExpectedChangeWindow for service tests.

    Using MagicMock (not __new__) avoids SQLAlchemy instrumentation issues when
    constructing model instances outside of a session.  All attributes accessed
    by the service layer and by ExpectedChangeWindowResponse.model_validate() are
    explicitly set.
    """
    now = _utcnow()
    window_id = uuid.uuid4()
    creator_id = uuid.uuid4()
    w = MagicMock()
    w.id = window_id
    w.workspace_id = workspace_id
    w.created_by_user_id = creator_id
    w.approved_by_user_id = None
    w.title = "Test window"
    w.description = None
    w.start_time = now + timedelta(hours=start_offset_hours)
    w.end_time = now + timedelta(hours=end_offset_hours)
    w.status = status
    w.alert_behavior = alert_behavior
    w.filter_provider = filter_provider
    w.filter_integration_id = filter_integration_id
    w.filter_risk_level = filter_risk_level
    w.rejection_reason = None
    w.approved_at = approved_at or (now if status == "approved" else None)
    w.created_at = now - timedelta(minutes=5)
    w.updated_at = now - timedelta(minutes=5)
    return w


# ── Test 1: create_window returns pending status ──────────────────────────────

def test_create_window_returns_pending():
    """Newly created window always starts in 'pending' status."""
    db = _mock_db()
    ws_id = uuid.uuid4()
    user_id = uuid.uuid4()

    body = _window_create()
    window = expected_change_service.create_window(ws_id, user_id, body, db)

    assert window.status == "pending"
    assert window.workspace_id == ws_id
    assert window.created_by_user_id == user_id
    assert window.title == "Deploy v2.1"
    assert window.alert_behavior == "annotate_only"
    db.add.assert_called_once_with(window)
    db.flush.assert_called_once()


# ── Test 2: create_window rejects end_time <= start_time ─────────────────────

def test_create_window_rejects_inverted_times():
    """start_time >= end_time raises ValueError."""
    db = _mock_db()
    now = _utcnow()

    body = ExpectedChangeWindowCreate(
        title="Bad window",
        start_time=now + timedelta(hours=4),
        end_time=now + timedelta(hours=2),  # end before start
        alert_behavior="annotate_only",
    )
    with pytest.raises(ValueError, match="start_time must be before end_time"):
        expected_change_service.create_window(uuid.uuid4(), uuid.uuid4(), body, db)


# ── Test 3: create_window rejects duration > 30 days ─────────────────────────

def test_create_window_rejects_excessive_duration():
    """Window duration > 30 days raises ValueError."""
    db = _mock_db()
    now = _utcnow()

    body = ExpectedChangeWindowCreate(
        title="Too long",
        start_time=now,
        end_time=now + timedelta(days=31),
        alert_behavior="annotate_only",
    )
    with pytest.raises(ValueError, match="30 days"):
        expected_change_service.create_window(uuid.uuid4(), uuid.uuid4(), body, db)


# ── Test 4: list_windows returns empty list for new workspace ─────────────────

def test_list_windows_empty():
    """list_windows returns an empty list when no windows exist."""
    db = _mock_db()
    ws_id = uuid.uuid4()

    # Simulate no rows returned
    mock_q = MagicMock()
    mock_q.filter.return_value = mock_q
    mock_q.order_by.return_value = mock_q
    mock_q.count.return_value = 0
    mock_q.offset.return_value.limit.return_value.all.return_value = []
    db.query.return_value = mock_q

    result = expected_change_service.list_windows(ws_id, db)
    assert result.total == 0
    assert result.windows == []


# ── Test 5: list_windows status filter is applied ────────────────────────────

def test_list_windows_status_filter():
    """list_windows passes status_filter to the query chain."""
    db = _mock_db()
    ws_id = uuid.uuid4()

    mock_q = MagicMock()
    mock_q.filter.return_value = mock_q
    mock_q.order_by.return_value = mock_q
    mock_q.count.return_value = 0
    mock_q.offset.return_value.limit.return_value.all.return_value = []
    db.query.return_value = mock_q

    expected_change_service.list_windows(ws_id, db, status_filter="approved")

    # At minimum two filter calls: workspace_id and status
    assert mock_q.filter.call_count >= 2


# ── Test 6: approve_window changes status to approved ────────────────────────

def test_approve_window_success():
    """approve_window transitions pending → approved and sets metadata."""
    db = _mock_db()
    ws_id = uuid.uuid4()
    approver_id = uuid.uuid4()

    window = _make_window(workspace_id=ws_id, status="pending")

    # Patch _get_window to return our synthetic window
    with patch.object(expected_change_service, "_get_window", return_value=window):
        result = expected_change_service.approve_window(
            ws_id, window.id, approver_id, db
        )

    assert result.status == "approved"
    assert result.approved_by_user_id == approver_id
    assert result.approved_at is not None
    db.flush.assert_called_once()


# ── Test 7: approve_window raises for non-pending status ─────────────────────

def test_approve_window_non_pending_raises():
    """Approving an already-approved window raises ValueError."""
    db = _mock_db()
    ws_id = uuid.uuid4()

    window = _make_window(workspace_id=ws_id, status="approved")

    with patch.object(expected_change_service, "_get_window", return_value=window):
        with pytest.raises(ValueError, match="Cannot approve"):
            expected_change_service.approve_window(ws_id, window.id, uuid.uuid4(), db)


# ── Test 8: reject_window transitions pending → rejected ─────────────────────

def test_reject_window_success():
    """reject_window transitions pending → rejected and stores the reason."""
    db = _mock_db()
    ws_id = uuid.uuid4()

    window = _make_window(workspace_id=ws_id, status="pending")

    with patch.object(expected_change_service, "_get_window", return_value=window):
        result = expected_change_service.reject_window(
            ws_id, window.id, db, reason="Not scheduled"
        )

    assert result.status == "rejected"
    assert result.rejection_reason == "Not scheduled"
    db.flush.assert_called_once()


# ── Test 9: reject_window raises for non-pending status ──────────────────────

def test_reject_window_non_pending_raises():
    """Rejecting an already-rejected window raises ValueError."""
    db = _mock_db()
    ws_id = uuid.uuid4()

    window = _make_window(workspace_id=ws_id, status="rejected")

    with patch.object(expected_change_service, "_get_window", return_value=window):
        with pytest.raises(ValueError, match="Cannot reject"):
            expected_change_service.reject_window(ws_id, window.id, db)


# ── Test 10: cancel_window from pending ──────────────────────────────────────

def test_cancel_window_from_pending():
    """cancel_window transitions pending → cancelled."""
    db = _mock_db()
    ws_id = uuid.uuid4()

    window = _make_window(workspace_id=ws_id, status="pending")

    with patch.object(expected_change_service, "_get_window", return_value=window):
        result = expected_change_service.cancel_window(ws_id, window.id, db)

    assert result.status == "cancelled"
    db.flush.assert_called_once()


# ── Test 11: cancel_window from approved ─────────────────────────────────────

def test_cancel_window_from_approved():
    """cancel_window transitions approved → cancelled."""
    db = _mock_db()
    ws_id = uuid.uuid4()

    window = _make_window(workspace_id=ws_id, status="approved")

    with patch.object(expected_change_service, "_get_window", return_value=window):
        result = expected_change_service.cancel_window(ws_id, window.id, db)

    assert result.status == "cancelled"


# ── Test 12: cancel_window from rejected raises ───────────────────────────────

def test_cancel_window_from_rejected_raises():
    """Cancelling a rejected window raises ValueError."""
    db = _mock_db()
    ws_id = uuid.uuid4()

    window = _make_window(workspace_id=ws_id, status="rejected")

    with patch.object(expected_change_service, "_get_window", return_value=window):
        with pytest.raises(ValueError, match="Cannot cancel"):
            expected_change_service.cancel_window(ws_id, window.id, db)


# ── Test 13: match_change returns False when no windows exist ─────────────────

def test_match_change_no_windows():
    """match_change returns matched=False when no approved windows exist."""
    db = _mock_db()
    change_id = uuid.uuid4()
    ws_id = uuid.uuid4()
    integ_id = uuid.uuid4()

    # Fake change and integration
    change = MagicMock()
    change.id = change_id
    change.integration_id = integ_id
    change.risk_level = "high"
    change.created_at = _utcnow()

    integ = MagicMock()
    integ.workspace_id = ws_id
    integ.provider = "cloudflare"

    db.get.side_effect = lambda model, pk: change if pk == change_id else integ

    # No candidate windows
    mock_q = MagicMock()
    mock_q.filter.return_value = mock_q
    mock_q.order_by.return_value = mock_q
    mock_q.all.return_value = []
    db.query.return_value = mock_q

    result = expected_change_service.match_change(change_id, db)
    assert result.matched is False
    assert result.window is None


# ── Test 14: match_change returns True within time window ────────────────────

def test_match_change_within_window():
    """match_change returns matched=True when change falls inside a window."""
    db = _mock_db()
    change_id = uuid.uuid4()
    ws_id = uuid.uuid4()
    integ_id = uuid.uuid4()
    now = _utcnow()

    change = MagicMock()
    change.id = change_id
    change.integration_id = integ_id
    change.risk_level = "high"
    change.created_at = now

    integ = MagicMock()
    integ.workspace_id = ws_id
    integ.provider = "cloudflare"

    db.get.side_effect = lambda model, pk: change if pk == change_id else integ

    # One approved window that covers now
    window = _make_window(
        workspace_id=ws_id,
        status="approved",
        start_offset_hours=-1.0,
        end_offset_hours=3.0,
    )

    mock_q = MagicMock()
    mock_q.filter.return_value = mock_q
    mock_q.order_by.return_value = mock_q
    mock_q.all.return_value = [window]
    db.query.return_value = mock_q

    result = expected_change_service.match_change(change_id, db)
    assert result.matched is True
    assert result.window is not None
    assert result.annotation is not None
    assert "Test window" in result.annotation


# ── Test 15: match_change returns False outside time window ──────────────────

def test_match_change_outside_window():
    """match_change returns False when no window SQL query returns no candidates."""
    db = _mock_db()
    change_id = uuid.uuid4()
    ws_id = uuid.uuid4()
    integ_id = uuid.uuid4()
    now = _utcnow()

    change = MagicMock()
    change.id = change_id
    change.integration_id = integ_id
    change.risk_level = "high"
    change.created_at = now - timedelta(days=3)  # old change

    integ = MagicMock()
    integ.workspace_id = ws_id
    integ.provider = "cloudflare"

    db.get.side_effect = lambda model, pk: change if pk == change_id else integ

    # No windows in DB-side filter result (DB handles time range)
    mock_q = MagicMock()
    mock_q.filter.return_value = mock_q
    mock_q.order_by.return_value = mock_q
    mock_q.all.return_value = []
    db.query.return_value = mock_q

    result = expected_change_service.match_change(change_id, db)
    assert result.matched is False


# ── Test 16: match_change provider filter match ───────────────────────────────

def test_match_change_provider_filter_match():
    """A window with filter_provider='cloudflare' matches a cloudflare change."""
    db = _mock_db()
    change_id = uuid.uuid4()
    ws_id = uuid.uuid4()
    integ_id = uuid.uuid4()
    now = _utcnow()

    change = MagicMock()
    change.id = change_id
    change.integration_id = integ_id
    change.risk_level = "medium"
    change.created_at = now

    integ = MagicMock()
    integ.workspace_id = ws_id
    integ.provider = "cloudflare"

    db.get.side_effect = lambda model, pk: change if pk == change_id else integ

    window = _make_window(
        workspace_id=ws_id,
        status="approved",
        start_offset_hours=-1.0,
        end_offset_hours=3.0,
        filter_provider="cloudflare",
    )

    mock_q = MagicMock()
    mock_q.filter.return_value = mock_q
    mock_q.order_by.return_value = mock_q
    mock_q.all.return_value = [window]
    db.query.return_value = mock_q

    result = expected_change_service.match_change(change_id, db)
    assert result.matched is True


# ── Test 17: match_change provider filter mismatch → False ───────────────────

def test_match_change_provider_filter_mismatch():
    """A window with filter_provider='github' does NOT match a cloudflare change."""
    db = _mock_db()
    change_id = uuid.uuid4()
    ws_id = uuid.uuid4()
    integ_id = uuid.uuid4()
    now = _utcnow()

    change = MagicMock()
    change.id = change_id
    change.integration_id = integ_id
    change.risk_level = "high"
    change.created_at = now

    integ = MagicMock()
    integ.workspace_id = ws_id
    integ.provider = "cloudflare"

    db.get.side_effect = lambda model, pk: change if pk == change_id else integ

    # Window filtered to "github" — should NOT match cloudflare change
    window = _make_window(
        workspace_id=ws_id,
        status="approved",
        start_offset_hours=-1.0,
        end_offset_hours=3.0,
        filter_provider="github",
    )

    mock_q = MagicMock()
    mock_q.filter.return_value = mock_q
    mock_q.order_by.return_value = mock_q
    mock_q.all.return_value = [window]
    db.query.return_value = mock_q

    result = expected_change_service.match_change(change_id, db)
    assert result.matched is False
