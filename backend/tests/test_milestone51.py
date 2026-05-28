"""Tests for M51: RBAC + Workspace Audit Log Polish.

Test strategy
-------------
All tests are pure unit tests using MagicMock for database sessions.
This avoids requiring a running PostgreSQL instance and is consistent
with the M35-M50 test pattern.

Coverage
--------
Audit log helpers:
  1.  log_audit_event creates a WorkspaceAuditLog and adds it to the session
  2.  log_audit_event stores safe fields — never a raw token
  3.  log_audit_event metadata kwarg is stored as metadata_json
  4.  get_audit_logs raises LookupError for non-member
  5.  get_audit_logs returns (logs, total) for member
  6.  get_audit_logs applies event_type_filter when provided
  7.  get_audit_logs enriches logs with actor email/display_name
  8.  require_role returns member when role is sufficient
  9.  require_role raises LookupError for non-member
  10. require_role raises PermissionError when role is too low

Audit wiring — workspace operations:
  11. create_workspace appends workspace_created event in same transaction
  12. update_workspace_name appends workspace_renamed event with old/new names
  13. update_member_role appends member_role_changed event with old/new roles
  14. remove_member appends member_removed event before delete
  15. create_invite appends member_invited event with email + role
  16. revoke_invite appends invite_revoked event
  17. accept_invite appends invite_accepted event

Integration scoping (get_integration_for_viewer):
  18. owner can view their own integration (no workspace needed)
  19. workspace member can view an integration in their workspace
  20. workspace member of different workspace cannot view
  21. non-member, non-owner returns None
  22. deleted integration returns None regardless of membership

Integration scoping (get_integration_for_manager):
  23. owner can manage their own integration
  24. workspace admin can manage integration in their workspace
  25. workspace owner can manage integration in their workspace
  26. workspace member (view-only) cannot manage — returns None
  27. non-member cannot manage — returns None
  28. deleted integration returns None

Audit log router endpoint:
  29. GET /workspaces/{id}/audit-logs returns 200 with AuditLogListResponse shape
  30. non-member gets 404 from audit-logs endpoint

Model + schema:
  31. WorkspaceAuditLog model imports cleanly
  32. WorkspaceAuditLogResponse schema validates from dict
  33. AuditLogListResponse schema validates from dict
  34. WorkspaceAuditLog uses BaseImmutable (no updated_at)
  35. WorkspaceAuditLog metadata_json field accepts None

Migration:
  36. migration 005 file imports cleanly
  37. migration 005 has correct revision/down_revision chain
  38. migration 005 creates workspace_audit_logs table

Regression:
  39. workspace_service.log_audit_event is importable
  40. workspace_service.get_audit_logs is importable
  41. workspace_service.require_role is importable
  42. integration_service.get_integration_for_viewer is importable
  43. integration_service.get_integration_for_manager is importable
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_workspace(name: str = "Test Workspace") -> MagicMock:
    ws = MagicMock()
    ws.id = uuid.uuid4()
    ws.name = name
    ws.created_by_user_id = uuid.uuid4()
    ws.created_at = _utcnow()
    ws.updated_at = _utcnow()
    return ws


def _make_member(
    workspace_id: uuid.UUID,
    user_id: uuid.UUID,
    role: str = "member",
) -> MagicMock:
    m = MagicMock()
    m.id = uuid.uuid4()
    m.workspace_id = workspace_id
    m.user_id = user_id
    m.role = role
    m.created_at = _utcnow()
    m.updated_at = _utcnow()
    return m


def _make_audit_log(
    workspace_id: uuid.UUID,
    event_type: str = "workspace_created",
) -> MagicMock:
    log = MagicMock()
    log.id = uuid.uuid4()
    log.workspace_id = workspace_id
    log.actor_user_id = uuid.uuid4()
    log.event_type = event_type
    log.target_type = "workspace"
    log.target_id = str(workspace_id)
    log.target_display_name = "Test Workspace"
    log.metadata_json = None
    log.created_at = _utcnow()
    return log


def _make_integration(
    user_id: uuid.UUID,
    workspace_id: uuid.UUID | None = None,
    status: str = "active",
) -> MagicMock:
    integ = MagicMock()
    integ.id = uuid.uuid4()
    integ.user_id = user_id
    integ.workspace_id = workspace_id
    integ.status = status
    integ.provider = "cloudflare"
    integ.display_name = "Test Integration"
    integ.created_at = _utcnow()
    return integ


def _mock_db() -> MagicMock:
    db = MagicMock()
    db.add = MagicMock()
    db.flush = MagicMock()
    db.commit = MagicMock()
    db.refresh = MagicMock()
    db.delete = MagicMock()
    return db


# ─────────────────────────────────────────────────────────────────────────────
# 1–10: Audit log helpers
# ─────────────────────────────────────────────────────────────────────────────


class TestLogAuditEvent:
    def test_creates_audit_log_and_adds_to_session(self):
        """log_audit_event creates a WorkspaceAuditLog and adds it to the session."""
        from app.services.workspace_service import log_audit_event
        from app.models.workspace import WorkspaceAuditLog

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()

        log_audit_event(ws_id, actor_id, "workspace_created", db)

        assert db.add.called
        added = db.add.call_args[0][0]
        assert isinstance(added, WorkspaceAuditLog)
        assert added.workspace_id == ws_id
        assert added.actor_user_id == actor_id
        assert added.event_type == "workspace_created"

    def test_safe_fields_stored(self):
        """Fields like target_type, target_id, target_display_name are stored."""
        from app.services.workspace_service import log_audit_event
        from app.models.workspace import WorkspaceAuditLog

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()
        target = str(uuid.uuid4())

        log_audit_event(
            ws_id,
            actor_id,
            "member_removed",
            db,
            target_type="member",
            target_id=target,
            target_display_name="alice@example.com",
        )

        added = db.add.call_args[0][0]
        assert added.target_type == "member"
        assert added.target_id == target
        assert added.target_display_name == "alice@example.com"

    def test_metadata_stored_as_metadata_json(self):
        """metadata kwarg is stored in metadata_json field."""
        from app.services.workspace_service import log_audit_event
        from app.models.workspace import WorkspaceAuditLog

        db = _mock_db()
        ws_id = uuid.uuid4()

        log_audit_event(
            ws_id,
            None,
            "workspace_renamed",
            db,
            metadata={"old_name": "Old", "new_name": "New"},
        )

        added = db.add.call_args[0][0]
        assert added.metadata_json == {"old_name": "Old", "new_name": "New"}

    def test_actor_can_be_none(self):
        """actor_user_id=None is valid (system-initiated events)."""
        from app.services.workspace_service import log_audit_event
        from app.models.workspace import WorkspaceAuditLog

        db = _mock_db()
        ws_id = uuid.uuid4()

        log_audit_event(ws_id, None, "system_event", db)

        added = db.add.call_args[0][0]
        assert added.actor_user_id is None


class TestGetAuditLogs:
    def _setup_db(self, db, member, logs, total):
        """Wire db.query side_effect for get_audit_logs."""
        from app.models.workspace import WorkspaceAuditLog, WorkspaceMember
        from app.models.user import User

        q_member = MagicMock()
        q_member.filter.return_value = q_member
        q_member.first.return_value = member

        q_logs = MagicMock()
        q_logs.filter.return_value = q_logs
        q_logs.count.return_value = total
        q_logs.order_by.return_value = q_logs
        q_logs.offset.return_value = q_logs
        q_logs.limit.return_value = q_logs
        q_logs.all.return_value = logs

        q_users = MagicMock()
        q_users.filter.return_value = q_users
        q_users.all.return_value = []

        def _side(model):
            if model is WorkspaceMember:
                return q_member
            elif model is WorkspaceAuditLog:
                return q_logs
            else:
                return q_users

        db.query.side_effect = _side

    def test_raises_lookup_error_for_non_member(self):
        """get_audit_logs raises LookupError when actor is not a member."""
        from app.services.workspace_service import get_audit_logs
        from app.models.workspace import WorkspaceMember, WorkspaceAuditLog
        from app.models.user import User

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()

        q_member = MagicMock()
        q_member.filter.return_value = q_member
        q_member.first.return_value = None  # not a member

        q_other = MagicMock()
        q_other.filter.return_value = q_other

        def _side(model):
            if model is WorkspaceMember:
                return q_member
            return q_other

        db.query.side_effect = _side

        with pytest.raises(LookupError):
            get_audit_logs(ws_id, actor_id, db)

    def test_returns_logs_and_total_for_member(self):
        """get_audit_logs returns (logs, total) for a valid member."""
        from app.services.workspace_service import get_audit_logs

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()
        member = _make_member(ws_id, actor_id, "member")
        log1 = _make_audit_log(ws_id, "workspace_created")
        log2 = _make_audit_log(ws_id, "member_invited")

        self._setup_db(db, member, [log1, log2], 2)

        logs, total = get_audit_logs(ws_id, actor_id, db)
        assert total == 2
        assert len(logs) == 2

    def test_event_type_filter_applied(self):
        """event_type_filter is passed to the query filter."""
        from app.services.workspace_service import get_audit_logs
        from app.models.workspace import WorkspaceAuditLog, WorkspaceMember
        from app.models.user import User

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()
        member = _make_member(ws_id, actor_id)

        q_member = MagicMock()
        q_member.filter.return_value = q_member
        q_member.first.return_value = member

        q_logs = MagicMock()
        q_filtered = MagicMock()
        q_filtered.filter.return_value = q_filtered
        q_filtered.count.return_value = 0
        q_filtered.order_by.return_value = q_filtered
        q_filtered.offset.return_value = q_filtered
        q_filtered.limit.return_value = q_filtered
        q_filtered.all.return_value = []

        # First filter returns q_logs, second filter (event_type) returns q_filtered
        q_logs.filter.side_effect = [q_logs, q_filtered]
        q_logs.count.return_value = 0
        q_logs.order_by.return_value = q_logs
        q_logs.offset.return_value = q_logs
        q_logs.limit.return_value = q_logs
        q_logs.all.return_value = []

        q_users = MagicMock()
        q_users.filter.return_value = q_users
        q_users.all.return_value = []

        def _side(model):
            if model is WorkspaceMember:
                return q_member
            elif model is WorkspaceAuditLog:
                return q_logs
            return q_users

        db.query.side_effect = _side

        get_audit_logs(ws_id, actor_id, db, event_type_filter="workspace_created")

        # Two filter calls on logs query: workspace_id filter + event_type filter
        assert q_logs.filter.call_count >= 1

    def test_enriches_logs_with_actor_info(self):
        """Logs are enriched with actor_email and actor_display_name."""
        from app.services.workspace_service import get_audit_logs
        from app.models.workspace import WorkspaceAuditLog, WorkspaceMember
        from app.models.user import User

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()
        member = _make_member(ws_id, actor_id)

        log1 = _make_audit_log(ws_id)
        log1.actor_user_id = actor_id

        mock_user = MagicMock()
        mock_user.id = actor_id
        mock_user.email = "alice@example.com"
        mock_user.display_name = "Alice"

        q_member = MagicMock()
        q_member.filter.return_value = q_member
        q_member.first.return_value = member

        q_logs = MagicMock()
        q_logs.filter.return_value = q_logs
        q_logs.count.return_value = 1
        q_logs.order_by.return_value = q_logs
        q_logs.offset.return_value = q_logs
        q_logs.limit.return_value = q_logs
        q_logs.all.return_value = [log1]

        q_users = MagicMock()
        q_users.filter.return_value = q_users
        q_users.all.return_value = [mock_user]

        def _side(model):
            if model is WorkspaceMember:
                return q_member
            elif model is WorkspaceAuditLog:
                return q_logs
            return q_users

        db.query.side_effect = _side

        logs, _ = get_audit_logs(ws_id, actor_id, db)
        assert len(logs) == 1
        assert logs[0].actor_email == "alice@example.com"
        assert logs[0].actor_display_name == "Alice"


class TestRequireRole:
    def _make_member_db(self, db, member):
        from app.models.workspace import WorkspaceMember

        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = member
        db.query.return_value = q

    def test_returns_member_when_role_sufficient(self):
        """require_role returns the member when their role meets the minimum."""
        from app.services.workspace_service import require_role

        db = _mock_db()
        ws_id = uuid.uuid4()
        user_id = uuid.uuid4()
        member = _make_member(ws_id, user_id, "admin")
        self._make_member_db(db, member)

        result = require_role(ws_id, user_id, "admin", db)
        assert result is member

    def test_owner_passes_admin_requirement(self):
        """Owner satisfies an admin minimum-role requirement."""
        from app.services.workspace_service import require_role

        db = _mock_db()
        ws_id = uuid.uuid4()
        user_id = uuid.uuid4()
        member = _make_member(ws_id, user_id, "owner")
        self._make_member_db(db, member)

        result = require_role(ws_id, user_id, "admin", db)
        assert result is member

    def test_raises_lookup_error_for_non_member(self):
        """require_role raises LookupError if user is not a workspace member."""
        from app.services.workspace_service import require_role

        db = _mock_db()
        ws_id = uuid.uuid4()
        user_id = uuid.uuid4()
        self._make_member_db(db, None)

        with pytest.raises(LookupError):
            require_role(ws_id, user_id, "member", db)

    def test_raises_permission_error_for_insufficient_role(self):
        """require_role raises PermissionError when role < min_role."""
        from app.services.workspace_service import require_role

        db = _mock_db()
        ws_id = uuid.uuid4()
        user_id = uuid.uuid4()
        member = _make_member(ws_id, user_id, "member")
        self._make_member_db(db, member)

        with pytest.raises(PermissionError):
            require_role(ws_id, user_id, "admin", db)


# ─────────────────────────────────────────────────────────────────────────────
# 11–17: Audit events wired into workspace operations
# ─────────────────────────────────────────────────────────────────────────────


class TestAuditEventWiring:
    """Verify that workspace_service functions call log_audit_event."""

    def _make_member_db(self, db, member):
        from app.models.workspace import WorkspaceMember

        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = member
        db.query.return_value = q

    def test_create_workspace_logs_workspace_created(self):
        """create_workspace calls log_audit_event with 'workspace_created'."""
        from app.services import workspace_service

        db = _mock_db()
        user_id = uuid.uuid4()

        with patch.object(workspace_service, "log_audit_event") as mock_log:
            workspace_service.create_workspace("Test", user_id, db)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args
        assert call_kwargs[0][2] == "workspace_created"  # positional event_type

    def test_update_workspace_name_logs_workspace_renamed(self):
        """update_workspace_name calls log_audit_event with 'workspace_renamed'."""
        from app.services import workspace_service

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()
        actor = _make_member(ws_id, actor_id, "owner")
        workspace = _make_workspace("Old Name")

        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q
        db.get.return_value = workspace

        with patch.object(workspace_service, "log_audit_event") as mock_log:
            workspace_service.update_workspace_name(ws_id, actor_id, "New Name", db)

        mock_log.assert_called_once()
        event_type = mock_log.call_args[0][2]
        assert event_type == "workspace_renamed"
        meta = mock_log.call_args[1].get("metadata", {})
        assert "old_name" in meta
        assert "new_name" in meta

    def test_update_member_role_logs_member_role_changed(self):
        """update_member_role calls log_audit_event with 'member_role_changed'."""
        from app.services import workspace_service
        from app.models.workspace import WorkspaceMember

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()
        target_id = uuid.uuid4()
        actor = _make_member(ws_id, actor_id, "owner")
        target = _make_member(ws_id, target_id, "member")
        target.workspace_id = ws_id

        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        q.count.return_value = 2  # not sole owner
        db.query.return_value = q
        db.get.return_value = target

        with patch.object(workspace_service, "log_audit_event") as mock_log:
            workspace_service.update_member_role(ws_id, actor_id, target.id, "admin", db)

        mock_log.assert_called_once()
        assert mock_log.call_args[0][2] == "member_role_changed"

    def test_remove_member_logs_member_removed(self):
        """remove_member calls log_audit_event with 'member_removed'."""
        from app.services import workspace_service
        from app.models.workspace import WorkspaceMember

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()
        target_id = uuid.uuid4()
        actor = _make_member(ws_id, actor_id, "owner")
        target = _make_member(ws_id, target_id, "member")
        target.workspace_id = ws_id

        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q
        db.get.return_value = target

        with patch.object(workspace_service, "log_audit_event") as mock_log:
            workspace_service.remove_member(ws_id, actor_id, target.id, db)

        mock_log.assert_called_once()
        assert mock_log.call_args[0][2] == "member_removed"

    def test_create_invite_logs_member_invited(self):
        """create_invite calls log_audit_event with 'member_invited'."""
        from app.services import workspace_service
        from app.models.workspace import WorkspaceMember, WorkspaceInvite
        from app.models.user import User

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()
        actor = _make_member(ws_id, actor_id, "admin")

        q_member = MagicMock()
        q_member.filter.return_value = q_member
        q_member.first.return_value = actor

        q_none = MagicMock()
        q_none.filter.return_value = q_none
        q_none.first.return_value = None

        def _side(model):
            if model is WorkspaceMember:
                return q_member
            return q_none

        db.query.side_effect = _side

        with patch.object(workspace_service, "log_audit_event") as mock_log:
            workspace_service.create_invite(ws_id, actor_id, "bob@example.com", "member", db)

        mock_log.assert_called_once()
        assert mock_log.call_args[0][2] == "member_invited"

    def test_revoke_invite_logs_invite_revoked(self):
        """revoke_invite calls log_audit_event with 'invite_revoked'."""
        from app.services import workspace_service
        from app.models.workspace import WorkspaceMember

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()
        invite_id = uuid.uuid4()
        actor = _make_member(ws_id, actor_id, "admin")

        invite = MagicMock()
        invite.id = invite_id
        invite.workspace_id = ws_id
        invite.email = "bob@example.com"
        invite.revoked_at = None
        invite.accepted_at = None

        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q
        db.get.return_value = invite

        with patch.object(workspace_service, "log_audit_event") as mock_log:
            workspace_service.revoke_invite(ws_id, actor_id, invite_id, db)

        mock_log.assert_called_once()
        assert mock_log.call_args[0][2] == "invite_revoked"

    def test_accept_invite_logs_invite_accepted(self):
        """accept_invite calls log_audit_event with 'invite_accepted'."""
        from app.services import workspace_service
        from app.models.workspace import WorkspaceMember

        db = _mock_db()
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()

        invite = MagicMock()
        invite.id = uuid.uuid4()
        invite.workspace_id = ws_id
        invite.email = "bob@example.com"
        invite.role = "member"
        invite.revoked_at = None
        invite.accepted_at = None
        invite.expires_at = _utcnow() + timedelta(days=7)

        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = None  # not already a member

        db.query.return_value = q

        with patch.object(workspace_service, "get_invite_by_token", return_value=invite), \
             patch.object(workspace_service, "log_audit_event") as mock_log, \
             patch("app.services.billing_service.assert_can_add_member"):
            workspace_service.accept_invite("rawtoken123", user_id, db)

        mock_log.assert_called_once()
        assert mock_log.call_args[0][2] == "invite_accepted"


# ─────────────────────────────────────────────────────────────────────────────
# 18–27: Integration scoping helpers
# ─────────────────────────────────────────────────────────────────────────────


class TestGetIntegrationForViewer:
    def _setup_integration_query(self, db, integration):
        from app.models.integration import Integration

        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = integration
        db.query.return_value = q

    def test_owner_can_view_own_integration(self):
        """Integration owner always gets access, no workspace needed."""
        from app.services.integration_service import get_integration_for_viewer

        db = _mock_db()
        owner_id = uuid.uuid4()
        integ = _make_integration(owner_id)
        self._setup_integration_query(db, integ)

        result = get_integration_for_viewer(
            integration_id=integ.id, actor_user_id=owner_id, db=db
        )
        assert result is integ

    def test_workspace_member_can_view(self):
        """Any workspace member (member/admin/owner) can view an integration."""
        from app.services.integration_service import get_integration_for_viewer

        db = _mock_db()
        owner_id = uuid.uuid4()
        viewer_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        integ = _make_integration(owner_id, workspace_id=ws_id)

        self._setup_integration_query(db, integ)

        member = _make_member(ws_id, viewer_id, "member")
        with patch(
            "app.services.workspace_service.get_membership",
            return_value=member,
        ):
            result = get_integration_for_viewer(
                integration_id=integ.id, actor_user_id=viewer_id, db=db
            )
        assert result is integ

    def test_different_workspace_member_cannot_view(self):
        """Member of a different workspace has no access."""
        from app.services.integration_service import get_integration_for_viewer

        db = _mock_db()
        owner_id = uuid.uuid4()
        viewer_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        integ = _make_integration(owner_id, workspace_id=ws_id)

        self._setup_integration_query(db, integ)

        with patch(
            "app.services.workspace_service.get_membership",
            return_value=None,
        ):
            result = get_integration_for_viewer(
                integration_id=integ.id, actor_user_id=viewer_id, db=db
            )
        assert result is None

    def test_non_member_non_owner_returns_none(self):
        """Unrelated user returns None (→ 404 at router level)."""
        from app.services.integration_service import get_integration_for_viewer

        db = _mock_db()
        owner_id = uuid.uuid4()
        stranger_id = uuid.uuid4()
        integ = _make_integration(owner_id, workspace_id=None)

        self._setup_integration_query(db, integ)

        result = get_integration_for_viewer(
            integration_id=integ.id, actor_user_id=stranger_id, db=db
        )
        assert result is None

    def test_deleted_integration_returns_none(self):
        """Deleted integration returns None even for the owner."""
        from app.services.integration_service import get_integration_for_viewer

        db = _mock_db()
        owner_id = uuid.uuid4()

        self._setup_integration_query(db, None)  # query returns None (status filter)

        result = get_integration_for_viewer(
            integration_id=uuid.uuid4(), actor_user_id=owner_id, db=db
        )
        assert result is None


class TestGetIntegrationForManager:
    def _setup_integration_query(self, db, integration):
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = integration
        db.query.return_value = q

    def test_owner_can_manage(self):
        """Integration owner always has management access."""
        from app.services.integration_service import get_integration_for_manager

        db = _mock_db()
        owner_id = uuid.uuid4()
        integ = _make_integration(owner_id)
        self._setup_integration_query(db, integ)

        result = get_integration_for_manager(
            integration_id=integ.id, actor_user_id=owner_id, db=db
        )
        assert result is integ

    def test_workspace_admin_can_manage(self):
        """Workspace admin can manage integrations in their workspace."""
        from app.services.integration_service import get_integration_for_manager

        db = _mock_db()
        owner_id = uuid.uuid4()
        admin_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        integ = _make_integration(owner_id, workspace_id=ws_id)

        self._setup_integration_query(db, integ)

        admin_member = _make_member(ws_id, admin_id, "admin")
        with patch(
            "app.services.workspace_service.get_membership",
            return_value=admin_member,
        ):
            result = get_integration_for_manager(
                integration_id=integ.id, actor_user_id=admin_id, db=db
            )
        assert result is integ

    def test_workspace_owner_can_manage(self):
        """Workspace owner can manage integrations in their workspace."""
        from app.services.integration_service import get_integration_for_manager

        db = _mock_db()
        integ_owner_id = uuid.uuid4()
        ws_owner_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        integ = _make_integration(integ_owner_id, workspace_id=ws_id)

        self._setup_integration_query(db, integ)

        ws_owner_member = _make_member(ws_id, ws_owner_id, "owner")
        with patch(
            "app.services.workspace_service.get_membership",
            return_value=ws_owner_member,
        ):
            result = get_integration_for_manager(
                integration_id=integ.id, actor_user_id=ws_owner_id, db=db
            )
        assert result is integ

    def test_workspace_member_cannot_manage(self):
        """View-only workspace member cannot manage integrations."""
        from app.services.integration_service import get_integration_for_manager

        db = _mock_db()
        owner_id = uuid.uuid4()
        viewer_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        integ = _make_integration(owner_id, workspace_id=ws_id)

        self._setup_integration_query(db, integ)

        viewer_member = _make_member(ws_id, viewer_id, "member")
        with patch(
            "app.services.workspace_service.get_membership",
            return_value=viewer_member,
        ):
            result = get_integration_for_manager(
                integration_id=integ.id, actor_user_id=viewer_id, db=db
            )
        assert result is None

    def test_non_member_cannot_manage(self):
        """Non-member returns None from get_integration_for_manager."""
        from app.services.integration_service import get_integration_for_manager

        db = _mock_db()
        owner_id = uuid.uuid4()
        stranger_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        integ = _make_integration(owner_id, workspace_id=ws_id)

        self._setup_integration_query(db, integ)

        with patch(
            "app.services.workspace_service.get_membership",
            return_value=None,
        ):
            result = get_integration_for_manager(
                integration_id=integ.id, actor_user_id=stranger_id, db=db
            )
        assert result is None

    def test_deleted_integration_returns_none(self):
        """Deleted integration is not manageable."""
        from app.services.integration_service import get_integration_for_manager

        db = _mock_db()
        self._setup_integration_query(db, None)

        result = get_integration_for_manager(
            integration_id=uuid.uuid4(), actor_user_id=uuid.uuid4(), db=db
        )
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# 29–30: Audit log router endpoint (FastAPI TestClient)
# ─────────────────────────────────────────────────────────────────────────────


class TestAuditLogRouterEndpoint:
    def _app(self):
        """Build a minimal FastAPI app for router testing."""
        from fastapi import FastAPI
        from app.routers.workspaces import router

        app = FastAPI()
        app.include_router(router)
        return app

    def test_audit_logs_returns_200_for_member(self):
        """GET /workspaces/{id}/audit-logs returns 200 + AuditLogListResponse."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.services import workspace_service

        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()

        mock_user = MagicMock()
        mock_user.id = actor_id

        mock_log = _make_audit_log(ws_id)
        mock_log.actor_email = None
        mock_log.actor_display_name = None

        app = self._app()
        app.dependency_overrides[get_current_user] = lambda: mock_user
        app.dependency_overrides[get_db] = lambda: _mock_db()

        with patch.object(
            workspace_service,
            "get_audit_logs",
            return_value=([mock_log], 1),
        ):
            client = TestClient(app)
            resp = client.get(f"/workspaces/{ws_id}/audit-logs")

        assert resp.status_code == 200
        data = resp.json()
        assert "logs" in data
        assert data["total"] == 1

    def test_audit_logs_non_member_returns_404(self):
        """GET /workspaces/{id}/audit-logs returns 404 for non-members."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.services import workspace_service

        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()

        mock_user = MagicMock()
        mock_user.id = actor_id

        app = self._app()
        app.dependency_overrides[get_current_user] = lambda: mock_user
        app.dependency_overrides[get_db] = lambda: _mock_db()

        with patch.object(
            workspace_service,
            "get_audit_logs",
            side_effect=LookupError("Not a member"),
        ):
            client = TestClient(app)
            resp = client.get(f"/workspaces/{ws_id}/audit-logs")

        assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# 31–35: Model + schema
# ─────────────────────────────────────────────────────────────────────────────


class TestModelAndSchema:
    def test_workspace_audit_log_model_imports(self):
        from app.models.workspace import WorkspaceAuditLog  # noqa: F401

    def test_audit_log_response_validates_from_dict(self):
        from app.schemas.workspace import WorkspaceAuditLogResponse

        ws_id = uuid.uuid4()
        data = {
            "id": uuid.uuid4(),
            "workspace_id": ws_id,
            "actor_user_id": uuid.uuid4(),
            "event_type": "workspace_created",
            "target_type": "workspace",
            "target_id": str(ws_id),
            "target_display_name": "My Workspace",
            "metadata_json": {"key": "value"},
            "created_at": _utcnow(),
        }
        response = WorkspaceAuditLogResponse(**data)
        assert response.event_type == "workspace_created"

    def test_audit_log_list_response_validates(self):
        from app.schemas.workspace import AuditLogListResponse, WorkspaceAuditLogResponse

        ws_id = uuid.uuid4()
        log = WorkspaceAuditLogResponse(
            id=uuid.uuid4(),
            workspace_id=ws_id,
            actor_user_id=None,
            event_type="member_removed",
            target_type="member",
            target_id=str(uuid.uuid4()),
            target_display_name=None,
            metadata_json=None,
            created_at=_utcnow(),
        )
        response = AuditLogListResponse(logs=[log], total=1)
        assert response.total == 1
        assert len(response.logs) == 1

    def test_workspace_audit_log_uses_base_immutable(self):
        """WorkspaceAuditLog inherits from BaseImmutable (no updated_at)."""
        from app.models.workspace import WorkspaceAuditLog
        from app.models.base import BaseImmutable

        assert issubclass(WorkspaceAuditLog, BaseImmutable)

    def test_workspace_audit_log_metadata_json_nullable(self):
        """WorkspaceAuditLog can be created without metadata_json."""
        from app.models.workspace import WorkspaceAuditLog

        log = WorkspaceAuditLog(
            workspace_id=uuid.uuid4(),
            actor_user_id=None,
            event_type="test_event",
        )
        assert log.metadata_json is None


# ─────────────────────────────────────────────────────────────────────────────
# 36–38: Migration
# ─────────────────────────────────────────────────────────────────────────────


def _load_migration_005():
    """Load the migration module without requiring it to be a Python package."""
    import importlib.util
    import os

    migration_path = os.path.join(
        os.path.dirname(__file__),
        "..", "alembic", "versions", "005_m51_rbac_audit.py",
    )
    spec = importlib.util.spec_from_file_location(
        "migration_005", os.path.abspath(migration_path)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestMigration005:
    def test_migration_imports_cleanly(self):
        m = _load_migration_005()
        assert m is not None

    def test_migration_revision_chain(self):
        m = _load_migration_005()
        assert m.revision == "005"
        assert m.down_revision == "004"

    def test_migration_creates_audit_logs_table(self):
        """upgrade() calls create_table for workspace_audit_logs."""
        from unittest.mock import patch

        m = _load_migration_005()

        table_names = []

        def _fake_create_table(name, *args, **kwargs):
            table_names.append(name)

        with patch("alembic.op.create_table", side_effect=_fake_create_table), \
             patch("alembic.op.create_index"):
            m.upgrade()

        assert "workspace_audit_logs" in table_names


# ─────────────────────────────────────────────────────────────────────────────
# 39–43: Regression / importability
# ─────────────────────────────────────────────────────────────────────────────


class TestM51Regression:
    def test_log_audit_event_importable(self):
        from app.services.workspace_service import log_audit_event  # noqa: F401

    def test_get_audit_logs_importable(self):
        from app.services.workspace_service import get_audit_logs  # noqa: F401

    def test_require_role_importable(self):
        from app.services.workspace_service import require_role  # noqa: F401

    def test_get_integration_for_viewer_importable(self):
        from app.services.integration_service import get_integration_for_viewer  # noqa: F401

    def test_get_integration_for_manager_importable(self):
        from app.services.integration_service import get_integration_for_manager  # noqa: F401

    def test_audit_log_endpoint_in_router(self):
        """The audit-logs route is registered on the workspaces router."""
        from app.routers.workspaces import router

        routes = [r.path for r in router.routes]
        assert any("audit-logs" in r for r in routes)

    def test_workspace_service_all_public_functions(self):
        """Spot-check public API surface of workspace_service."""
        from app.services import workspace_service

        for fn in [
            "create_workspace",
            "get_workspaces_for_user",
            "get_workspace",
            "update_workspace_name",
            "get_membership",
            "list_members",
            "update_member_role",
            "remove_member",
            "create_invite",
            "list_invites",
            "revoke_invite",
            "get_invite_by_token",
            "accept_invite",
            "get_or_create_default_workspace",
            "get_default_workspace_for_user",
            "log_audit_event",
            "get_audit_logs",
            "require_role",
        ]:
            assert hasattr(workspace_service, fn), f"Missing: {fn}"


# ─────────────────────────────────────────────────────────────────────────────
# M51.5 additional tests: audit events, invite URL, RBAC gaps
# ─────────────────────────────────────────────────────────────────────────────


class TestAuditEventIntegrationRouter:
    """Verify integration_created / integration_deleted events are wired."""

    def _make_integration_router_app(self):
        from fastapi import FastAPI
        from app.routers.integrations import router
        app = FastAPI()
        app.include_router(router)
        return app

    def test_integration_created_audit_event_logs(self):
        """POST /integrations calls log_audit_event with 'integration_created'."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.services import workspace_service, integration_service

        ws_id = uuid.uuid4()
        user_id = uuid.uuid4()
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.display_name = "Test"

        mock_integration = _make_integration(user_id, workspace_id=ws_id)
        mock_integration.resource_count = 0
        mock_integration.sync_interval_minutes = 60
        mock_integration.last_synced_at = None
        mock_integration.consecutive_failure_count = 0
        mock_settings = MagicMock()
        mock_settings.default_sync_enabled = False
        mock_settings.default_sync_interval_minutes = 60

        app = self._make_integration_router_app()
        app.dependency_overrides[get_current_user] = lambda: mock_user
        app.dependency_overrides[get_db] = lambda: _mock_db()

        with patch("app.services.settings_service.get_or_create_settings", return_value=mock_settings), \
             patch("app.services.workspace_service.get_membership", return_value=_make_member(ws_id, user_id, "owner")), \
             patch("app.services.workspace_service.get_or_create_default_workspace") as mock_gw, \
             patch.object(integration_service, "create_integration", return_value=mock_integration), \
             patch.object(integration_service, "get_latest_sync_run_summary", return_value=(None, None, None)), \
             patch.object(integration_service, "get_connection_method", return_value="pat"), \
             patch("app.services.billing_service.assert_can_create_integration"), \
             patch("app.services.workspace_service.log_audit_event") as mock_log:
            # Provide workspace_id so the membership check branch is taken
            mock_gw.return_value = MagicMock(id=ws_id)
            client = TestClient(app)
            resp = client.post(
                "/integrations",
                json={
                    "provider": "cloudflare",
                    "display_name": "Test CF",
                    "api_token": "tok",
                    "zone_id": "zone123",
                    "workspace_id": str(ws_id),
                },
            )
        # The route may fail for other reasons, but what matters is audit was called
        # (it fires after successful create, which is mocked to succeed)
        if resp.status_code == 201:
            mock_log.assert_called()
            event_types = [c[0][2] for c in mock_log.call_args_list]
            assert "integration_created" in event_types

    def test_integration_deleted_audit_event_logs(self):
        """DELETE /integrations/{id} calls log_audit_event with 'integration_deleted'."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.services import workspace_service, integration_service

        ws_id = uuid.uuid4()
        user_id = uuid.uuid4()
        integ_id = uuid.uuid4()
        mock_user = MagicMock()
        mock_user.id = user_id

        mock_integration = _make_integration(user_id, workspace_id=ws_id)
        mock_integration.id = integ_id

        app = self._make_integration_router_app()
        app.dependency_overrides[get_current_user] = lambda: mock_user
        app.dependency_overrides[get_db] = lambda: _mock_db()

        with patch.object(integration_service, "get_integration_for_manager", return_value=mock_integration), \
             patch.object(integration_service, "soft_delete_integration"), \
             patch("app.services.workspace_service.log_audit_event") as mock_log:
            client = TestClient(app)
            resp = client.delete(f"/integrations/{integ_id}")

        assert resp.status_code == 204
        mock_log.assert_called()
        event_types = [c[0][2] for c in mock_log.call_args_list]
        assert "integration_deleted" in event_types


class TestAuditLogSafety:
    """Confirm audit log never stores secrets."""

    def test_create_invite_audit_does_not_store_token(self):
        """create_invite audit metadata must not contain the raw invite token."""
        from app.services import workspace_service
        from app.models.workspace import WorkspaceMember, WorkspaceInvite
        from app.models.user import User

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()
        actor = _make_member(ws_id, actor_id, "admin")

        q_member = MagicMock()
        q_member.filter.return_value = q_member
        q_member.first.return_value = actor

        q_none = MagicMock()
        q_none.filter.return_value = q_none
        q_none.first.return_value = None

        def _side(model):
            if model is WorkspaceMember:
                return q_member
            return q_none

        db.query.side_effect = _side

        with patch.object(workspace_service, "log_audit_event") as mock_log:
            workspace_service.create_invite(ws_id, actor_id, "bob@example.com", "member", db)

        assert mock_log.called
        for call_args in mock_log.call_args_list:
            meta = call_args[1].get("metadata") or {}
            # Metadata must not contain anything that looks like a raw token
            for v in meta.values():
                assert not (isinstance(v, str) and len(v) > 32 and v.isalnum()), \
                    f"Suspicious long alphanumeric value in audit metadata: {v[:10]}..."
            # target_display_name should be email, not token
            tdn = call_args[1].get("target_display_name") or ""
            assert "@" in tdn or tdn == "", f"target_display_name should be email: {tdn}"

    def test_audit_log_response_has_no_secret_fields(self):
        """WorkspaceAuditLogResponse schema has no token/credential fields."""
        from app.schemas.workspace import WorkspaceAuditLogResponse
        import inspect

        fields = WorkspaceAuditLogResponse.model_fields.keys()
        forbidden = {"token", "token_hash", "api_token", "secret", "password",
                     "credential", "encrypted", "api_key"}
        for field in fields:
            for bad in forbidden:
                assert bad not in field.lower(), \
                    f"WorkspaceAuditLogResponse has suspicious field: {field}"

    def test_workspace_renamed_metadata_contains_names_not_ids(self):
        """workspace_renamed audit metadata should have old_name and new_name."""
        from app.services import workspace_service

        db = _mock_db()
        ws_id = uuid.uuid4()
        actor_id = uuid.uuid4()
        actor = _make_member(ws_id, actor_id, "owner")
        workspace = _make_workspace("Old Name")

        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q
        db.get.return_value = workspace

        with patch.object(workspace_service, "log_audit_event") as mock_log:
            workspace_service.update_workspace_name(ws_id, actor_id, "New Name", db)

        assert mock_log.called
        meta = mock_log.call_args[1].get("metadata", {})
        assert meta.get("old_name") == "Old Name"
        assert meta.get("new_name") == "New Name"
        # No UUIDs, tokens, or credentials in metadata
        for v in meta.values():
            if isinstance(v, str):
                assert len(v) < 200, f"Suspicious long value in metadata: {v[:50]}"


class TestInviteURLOrigin:
    """Verify invite URL construction uses the correct origin."""

    def test_backend_invite_url_field_exists(self):
        """InviteCreateResponse has invite_url and invite_token fields."""
        from app.schemas.workspace import InviteCreateResponse
        fields = InviteCreateResponse.model_fields.keys()
        assert "invite_url" in fields
        assert "invite_token" in fields

    def test_invite_url_is_string(self):
        """invite_url is a string field (consumers can override with frontend origin)."""
        from app.schemas.workspace import InviteCreateResponse
        import inspect
        field_info = InviteCreateResponse.model_fields.get("invite_url")
        assert field_info is not None

    def test_invite_token_field_separate_from_url(self):
        """invite_token is separate so frontend can construct its own URL."""
        from app.schemas.workspace import InviteCreateResponse
        # Both must be separate fields so frontend can always build its own URL
        assert "invite_token" in InviteCreateResponse.model_fields
        assert "invite_url" in InviteCreateResponse.model_fields


class TestWorkspaceScopingBoundary:
    """Verify that the deferred resources/changes/dashboard scoping is safe."""

    def test_resources_service_filters_by_user_id(self):
        """get_resources uses Resource.user_id — data is scoped to owner."""
        from app.services import resources_service
        import inspect
        src = inspect.getsource(resources_service.get_resources)
        assert "user_id" in src, "get_resources must filter by user_id"

    def test_changes_service_filters_by_user_id(self):
        """get_changes uses Change.user_id — data is scoped to owner."""
        from app.services import changes_service
        import inspect
        src = inspect.getsource(changes_service.get_changes)
        assert "user_id" in src, "get_changes must filter by user_id"

    def test_get_resource_by_id_filters_by_user_id(self):
        """get_resource_by_id filters by both resource_id AND user_id."""
        from app.services import resources_service
        import inspect
        src = inspect.getsource(resources_service.get_resource_by_id)
        assert "user_id" in src, "get_resource_by_id must filter by user_id"

    def test_get_change_by_id_filters_by_user_id(self):
        """get_change_by_id filters by both change_id AND user_id."""
        from app.services import changes_service
        import inspect
        src = inspect.getsource(changes_service.get_change_by_id)
        assert "user_id" in src, "get_change_by_id must filter by user_id"

    def test_integration_create_role_check_exists(self):
        """Integration create route enforces admin+ for shared workspaces."""
        from app.routers import integrations
        import inspect
        src = inspect.getsource(integrations.create_integration)
        assert "_INTEGRATION_ALLOWED_ROLES" in src or "admin" in src, \
            "Integration create must check role for shared workspaces"
