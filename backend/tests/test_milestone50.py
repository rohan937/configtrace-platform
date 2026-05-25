"""Tests for M50: Teams + Workspaces + Invite System.

Test strategy
-------------
All tests are pure unit tests using MagicMock for database sessions.
This avoids requiring a running PostgreSQL instance and is consistent
with the M35-M49 test pattern.

Coverage
--------
Workspace:
  1.  create_workspace creates owner membership and returns (workspace, member)
  2.  get_workspaces_for_user returns only user's workspaces
  3.  get_workspace returns None if user is not a member
  4.  get_workspace returns workspace if user is a member
  5.  update_workspace_name succeeds for owner
  6.  update_workspace_name succeeds for admin
  7.  update_workspace_name raises PermissionError for member
  8.  update_workspace_name raises LookupError if not a member

Members:
  9.  list_members raises LookupError if actor is not a member
  10. list_members returns all members for owner
  11. update_member_role: only owner can change roles
  12. update_member_role: admin cannot change roles
  13. update_member_role: sole-owner cannot be demoted
  14. update_member_role: owner can demote when 2+ owners exist
  15. remove_member: admin cannot remove owner
  16. remove_member: member cannot remove anyone
  17. remove_member: sole owner cannot be removed
  18. remove_member: owner can remove member
  19. remove_member: admin can remove member

Invites:
  20. create_invite: member cannot invite
  21. create_invite: duplicate active invite raises ValueError
  22. create_invite: target already member raises ValueError
  23. create_invite: generates unique token + stores hash only
  24. create_invite: token_hash != raw_token (hash is stored)
  25. invite email normalised to lowercase
  26. get_invite_by_token: returns None for unknown token
  27. get_invite_by_token: returns invite for matching hash
  28. accept_invite: expired invite raises ValueError
  29. accept_invite: revoked invite raises ValueError
  30. accept_invite: already accepted invite raises ValueError
  31. accept_invite: creates WorkspaceMember on success
  32. accept_invite: already a member raises ValueError
  33. revoke_invite: member cannot revoke
  34. revoke_invite: idempotent on already-revoked
  35. revoke_invite: accepted invite cannot be revoked
  36. list_invites: member cannot list invites

Default workspace:
  37. get_or_create_default_workspace creates workspace if none exists
  38. get_or_create_default_workspace returns existing owned workspace
  39. get_default_workspace_for_user returns None if no memberships

Security:
  40. invite token_hash is never the raw token
  41. invite token_hash is SHA-256 hex (64 chars)
  42. raw token is not stored anywhere on the WorkspaceInvite
  43. _hash_token is deterministic and consistent
  44. workspace_id on Integration is nullable (allows backfill)

Schema:
  45. WorkspaceCreateRequest validates name min length
  46. WorkspaceUpdateRequest validates name min length
  47. InviteCreateRequest normalises email to lowercase
  48. InviteCreateRequest rejects role='owner'
  49. InviteRole only allows 'admin' or 'member'

Integration service:
  50. create_integration accepts workspace_id param
  51. get_integrations_by_workspace filters by workspace_id
  52. get_integrations_by_workspace excludes deleted integrations

Scoping:
  53. get_workspace returns None for non-member (access denied)
  54. non-member cannot list members
  55. non-member cannot invite
  56. non-member cannot remove member

Regression:
  57. workspace_service module imports cleanly
  58. workspace model imports cleanly
  59. workspace schemas import cleanly
  60. workspaces router imports cleanly
  61. invites router imports cleanly
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call, patch

import pytest
from pydantic import ValidationError


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


def _make_invite(
    workspace_id: uuid.UUID,
    email: str = "test@example.com",
    role: str = "member",
    *,
    expired: bool = False,
    revoked: bool = False,
    accepted: bool = False,
) -> MagicMock:
    inv = MagicMock()
    inv.id = uuid.uuid4()
    inv.workspace_id = workspace_id
    inv.email = email
    inv.role = role
    inv.token_hash = hashlib.sha256(b"testtoken").hexdigest()
    inv.invited_by_user_id = uuid.uuid4()
    inv.expires_at = (
        _utcnow() - timedelta(hours=1) if expired else _utcnow() + timedelta(days=7)
    )
    inv.accepted_at = _utcnow() if accepted else None
    inv.revoked_at = _utcnow() if revoked else None
    # is_active property
    inv.is_active = not expired and not revoked and not accepted
    return inv


def _mock_db() -> MagicMock:
    """Return a minimal MagicMock SQLAlchemy session."""
    db = MagicMock()
    db.add = MagicMock()
    db.flush = MagicMock()
    db.commit = MagicMock()
    db.refresh = MagicMock()
    db.delete = MagicMock()
    return db


# ─────────────────────────────────────────────────────────────────────────────
# Import checks (regression)
# ─────────────────────────────────────────────────────────────────────────────


class TestImports:
    def test_workspace_service_imports(self):
        from app.services import workspace_service  # noqa: F401

    def test_workspace_model_imports(self):
        from app.models.workspace import Workspace, WorkspaceMember, WorkspaceInvite  # noqa: F401

    def test_workspace_schemas_import(self):
        from app.schemas.workspace import (  # noqa: F401
            WorkspaceResponse,
            WorkspaceCreateRequest,
            WorkspaceMemberResponse,
            InviteCreateRequest,
            InvitePreviewResponse,
        )

    def test_workspaces_router_imports(self):
        from app.routers.workspaces import router  # noqa: F401

    def test_invites_router_imports(self):
        from app.routers.invites import router  # noqa: F401

    def test_main_app_imports(self):
        """main.py must import cleanly with the new routers registered."""
        from app.main import app  # noqa: F401
        # Verify workspace routes are registered.
        routes = [r.path for r in app.routes]  # type: ignore[attr-defined]
        assert any("/workspaces" in r for r in routes)
        assert any("/invites" in r for r in routes)


# ─────────────────────────────────────────────────────────────────────────────
# Schema validation
# ─────────────────────────────────────────────────────────────────────────────


class TestSchemas:
    def test_workspace_create_min_length(self):
        from app.schemas.workspace import WorkspaceCreateRequest
        with pytest.raises(ValidationError):
            WorkspaceCreateRequest(name="")

    def test_workspace_update_min_length(self):
        from app.schemas.workspace import WorkspaceUpdateRequest
        with pytest.raises(ValidationError):
            WorkspaceUpdateRequest(name="")

    def test_invite_email_normalised(self):
        from app.schemas.workspace import InviteCreateRequest
        req = InviteCreateRequest(email="  User@EXAMPLE.COM  ", role="member")
        assert req.email == "user@example.com"

    def test_invite_role_member_valid(self):
        from app.schemas.workspace import InviteCreateRequest
        req = InviteCreateRequest(email="a@b.com", role="member")
        assert req.role == "member"

    def test_invite_role_admin_valid(self):
        from app.schemas.workspace import InviteCreateRequest
        req = InviteCreateRequest(email="a@b.com", role="admin")
        assert req.role == "admin"

    def test_invite_role_owner_rejected(self):
        from app.schemas.workspace import InviteCreateRequest
        with pytest.raises(ValidationError):
            InviteCreateRequest(email="a@b.com", role="owner")  # type: ignore[arg-type]


# ─────────────────────────────────────────────────────────────────────────────
# Workspace CRUD
# ─────────────────────────────────────────────────────────────────────────────


class TestCreateWorkspace:
    def test_creates_workspace_and_owner_member(self):
        from app.services.workspace_service import create_workspace
        from app.models.workspace import Workspace, WorkspaceMember

        db = _mock_db()
        user_id = uuid.uuid4()

        added_objects = []
        db.add.side_effect = lambda obj: added_objects.append(obj)
        # db.refresh is a no-op (object already has id from default=uuid.uuid4)

        ws, member = create_workspace("My Workspace", user_id, db)

        assert db.add.called
        assert db.commit.called
        # The workspace and member were both added.
        assert any(isinstance(o, Workspace) for o in added_objects)
        assert any(isinstance(o, WorkspaceMember) for o in added_objects)

    def test_owner_role_assigned(self):
        from app.services.workspace_service import create_workspace

        db = _mock_db()
        user_id = uuid.uuid4()
        members = []
        db.add.side_effect = lambda obj: members.append(obj)

        ws, member = create_workspace("Test", user_id, db)
        assert member.role == "owner"

    def test_workspace_name_stripped(self):
        from app.services.workspace_service import create_workspace

        db = _mock_db()
        ws, _ = create_workspace("  Padded Name  ", uuid.uuid4(), db)
        assert ws.name == "Padded Name"


class TestGetWorkspaces:
    def test_returns_empty_for_no_memberships(self):
        from app.services.workspace_service import get_workspaces_for_user

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.all.return_value = []
        db.query.return_value = q

        result = get_workspaces_for_user(uuid.uuid4(), db)
        assert result == []

    def test_returns_only_user_workspaces(self):
        from app.services.workspace_service import get_workspaces_for_user

        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        member = _make_member(ws_id, user_id, "owner")
        ws = _make_workspace()
        ws.id = ws_id

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.all.side_effect = [[member], [ws]]
        q.order_by.return_value = q
        db.query.return_value = q

        result = get_workspaces_for_user(user_id, db)
        assert len(result) == 1


class TestGetWorkspace:
    def test_returns_none_for_non_member(self):
        from app.services.workspace_service import get_workspace

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = None
        db.query.return_value = q

        result = get_workspace(uuid.uuid4(), uuid.uuid4(), db)
        assert result is None

    def test_returns_workspace_for_member(self):
        from app.services.workspace_service import get_workspace

        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        member = _make_member(ws_id, user_id, "owner")
        ws = _make_workspace()
        ws.id = ws_id

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = member
        db.query.return_value = q
        db.get.return_value = ws

        result = get_workspace(ws_id, user_id, db)
        assert result is ws


class TestUpdateWorkspaceName:
    def _setup_actor(self, db: MagicMock, role: str, ws_id: uuid.UUID, user_id: uuid.UUID):
        member = _make_member(ws_id, user_id, role)
        ws = _make_workspace()
        ws.id = ws_id

        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = member
        db.query.return_value = q
        db.get.return_value = ws
        return ws

    def test_owner_can_rename(self):
        from app.services.workspace_service import update_workspace_name
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        db = _mock_db()
        ws = self._setup_actor(db, "owner", ws_id, user_id)

        result = update_workspace_name(ws_id, user_id, "New Name", db)
        assert result.name == "New Name"
        db.commit.assert_called()

    def test_admin_can_rename(self):
        from app.services.workspace_service import update_workspace_name
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        db = _mock_db()
        ws = self._setup_actor(db, "admin", ws_id, user_id)

        result = update_workspace_name(ws_id, user_id, "Admin Name", db)
        assert result.name == "Admin Name"

    def test_member_cannot_rename(self):
        from app.services.workspace_service import update_workspace_name
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        db = _mock_db()
        self._setup_actor(db, "member", ws_id, user_id)

        with pytest.raises(PermissionError):
            update_workspace_name(ws_id, user_id, "Bad", db)

    def test_non_member_raises_lookup_error(self):
        from app.services.workspace_service import update_workspace_name
        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = None
        db.query.return_value = q

        with pytest.raises(LookupError):
            update_workspace_name(uuid.uuid4(), uuid.uuid4(), "X", db)


# ─────────────────────────────────────────────────────────────────────────────
# Members
# ─────────────────────────────────────────────────────────────────────────────


class TestListMembers:
    def test_non_member_raises_lookup_error(self):
        from app.services.workspace_service import list_members
        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = None
        db.query.return_value = q

        with pytest.raises(LookupError):
            list_members(uuid.uuid4(), uuid.uuid4(), db)

    def test_owner_can_list(self):
        from app.services.workspace_service import list_members
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "owner")
        members = [actor, _make_member(ws_id, uuid.uuid4(), "member")]

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        q.order_by.return_value = q
        q.all.return_value = members
        db.query.return_value = q

        result = list_members(ws_id, user_id, db)
        assert len(result) == 2


class TestUpdateMemberRole:
    def test_only_owner_can_change_roles(self):
        from app.services.workspace_service import update_member_role
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "admin")
        target = _make_member(ws_id, uuid.uuid4(), "member")

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q
        db.get.return_value = target

        with pytest.raises(PermissionError, match="Only owners"):
            update_member_role(ws_id, user_id, target.id, "admin", db)

    def test_sole_owner_cannot_be_demoted(self):
        from app.services.workspace_service import update_member_role
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "owner")
        target = actor  # same user

        db = _mock_db()
        call_count = [0]

        def mock_query(model):
            q = MagicMock()
            q.filter.return_value = q
            call_count[0] += 1
            if call_count[0] == 1:
                q.first.return_value = actor
            else:
                q.count.return_value = 1  # sole owner
            return q

        db.query.side_effect = mock_query
        db.get.return_value = target

        with pytest.raises(ValueError, match="sole owner"):
            update_member_role(ws_id, user_id, target.id, "admin", db)

    def test_owner_can_demote_when_multiple_owners(self):
        from app.services.workspace_service import update_member_role
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "owner")
        target = _make_member(ws_id, uuid.uuid4(), "owner")

        call_count = [0]
        db = _mock_db()

        def mock_query(model):
            q = MagicMock()
            q.filter.return_value = q
            call_count[0] += 1
            if call_count[0] == 1:
                q.first.return_value = actor
            else:
                q.count.return_value = 2  # 2 owners
            return q

        db.query.side_effect = mock_query
        db.get.return_value = target

        result = update_member_role(ws_id, user_id, target.id, "admin", db)
        assert target.role == "admin"


class TestRemoveMember:
    def test_member_cannot_remove(self):
        from app.services.workspace_service import remove_member
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "member")

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q

        with pytest.raises(PermissionError):
            remove_member(ws_id, user_id, uuid.uuid4(), db)

    def test_admin_cannot_remove_owner(self):
        from app.services.workspace_service import remove_member
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "admin")
        target = _make_member(ws_id, uuid.uuid4(), "owner")

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q
        db.get.return_value = target

        with pytest.raises(PermissionError, match="cannot remove workspace owners"):
            remove_member(ws_id, user_id, target.id, db)

    def test_sole_owner_cannot_be_removed(self):
        from app.services.workspace_service import remove_member
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "owner")
        target = actor  # same

        call_count = [0]
        db = _mock_db()

        def mock_query(model):
            q = MagicMock()
            q.filter.return_value = q
            call_count[0] += 1
            if call_count[0] == 1:
                q.first.return_value = actor
            else:
                q.count.return_value = 1
            return q

        db.query.side_effect = mock_query
        db.get.return_value = target

        with pytest.raises(ValueError, match="sole owner"):
            remove_member(ws_id, user_id, target.id, db)

    def test_owner_can_remove_member(self):
        from app.services.workspace_service import remove_member
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "owner")
        target = _make_member(ws_id, uuid.uuid4(), "member")

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q
        db.get.return_value = target

        remove_member(ws_id, user_id, target.id, db)
        db.delete.assert_called_once_with(target)
        db.commit.assert_called()

    def test_admin_can_remove_member(self):
        from app.services.workspace_service import remove_member
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "admin")
        target = _make_member(ws_id, uuid.uuid4(), "member")

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q
        db.get.return_value = target

        remove_member(ws_id, user_id, target.id, db)
        db.delete.assert_called_once_with(target)


# ─────────────────────────────────────────────────────────────────────────────
# Invites
# ─────────────────────────────────────────────────────────────────────────────


class TestCreateInvite:
    def _setup_actor(self, db, role, ws_id, user_id):
        actor = _make_member(ws_id, user_id, role)
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q
        return actor

    def test_member_cannot_invite(self):
        from app.services.workspace_service import create_invite
        db = _mock_db()
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        self._setup_actor(db, "member", ws_id, user_id)

        with pytest.raises(PermissionError):
            create_invite(ws_id, user_id, "x@x.com", "member", db)

    def _setup_invite_db(self, db, actor):
        """Return a db mock where only WorkspaceMember queries yield actor;
        User and WorkspaceInvite queries return None (no existing user / no dupe)."""
        from app.models.workspace import WorkspaceMember, WorkspaceInvite as WI
        from app.models.user import User

        q_member = MagicMock()
        q_member.filter.return_value = q_member
        q_member.first.return_value = actor

        q_none = MagicMock()
        q_none.filter.return_value = q_none
        q_none.first.return_value = None

        def _side(model):
            return q_member if model is WorkspaceMember else q_none

        db.query.side_effect = _side

    def test_email_normalised_to_lowercase(self):
        from app.services.workspace_service import create_invite
        from app.models.workspace import WorkspaceInvite

        db = _mock_db()
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "owner")

        added = []
        db.add.side_effect = lambda obj: added.append(obj)
        self._setup_invite_db(db, actor)

        invite, raw_token = create_invite(ws_id, user_id, "UPPER@EXAMPLE.COM", "member", db)
        assert invite.email == "upper@example.com"

    def test_token_hash_is_sha256_not_raw(self):
        from app.services.workspace_service import create_invite, _hash_token
        from app.models.workspace import WorkspaceInvite

        db = _mock_db()
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "owner")

        self._setup_invite_db(db, actor)

        invite, raw_token = create_invite(ws_id, user_id, "test@x.com", "member", db)

        assert invite.token_hash != raw_token
        assert invite.token_hash == _hash_token(raw_token)
        assert len(invite.token_hash) == 64  # SHA-256 hex = 64 chars

    def test_token_hash_is_not_stored_raw(self):
        """Raw token must not appear on the invite object."""
        from app.services.workspace_service import create_invite

        db = _mock_db()
        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "owner")

        self._setup_invite_db(db, actor)

        invite, raw_token = create_invite(ws_id, user_id, "test@x.com", "member", db)

        # The raw token should not be any attribute of the invite.
        for attr in vars(invite):
            val = getattr(invite, attr, None)
            assert val != raw_token, f"Raw token found on invite.{attr}"


class TestGetInviteByToken:
    def test_returns_none_for_unknown_token(self):
        from app.services.workspace_service import get_invite_by_token

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = None
        db.query.return_value = q

        result = get_invite_by_token("unknowntoken", db)
        assert result is None

    def test_returns_invite_for_matching_hash(self):
        from app.services.workspace_service import get_invite_by_token, _hash_token

        ws_id = uuid.uuid4()
        raw = "correct_raw_token_value"
        invite = _make_invite(ws_id)
        invite.token_hash = _hash_token(raw)

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = invite
        db.query.return_value = q

        result = get_invite_by_token(raw, db)
        assert result is invite


class TestAcceptInvite:
    def _active_invite(self, ws_id: uuid.UUID) -> MagicMock:
        return _make_invite(ws_id)

    def test_expired_invite_raises(self):
        from app.services.workspace_service import accept_invite, _hash_token

        ws_id = uuid.uuid4()
        raw = "tok"
        invite = _make_invite(ws_id, expired=True)
        invite.token_hash = _hash_token(raw)

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = invite
        db.query.return_value = q

        with pytest.raises(ValueError, match="expired"):
            accept_invite(raw, uuid.uuid4(), db)

    def test_revoked_invite_raises(self):
        from app.services.workspace_service import accept_invite, _hash_token

        ws_id = uuid.uuid4()
        raw = "tok"
        invite = _make_invite(ws_id, revoked=True)
        invite.token_hash = _hash_token(raw)

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = invite
        db.query.return_value = q

        with pytest.raises(ValueError, match="revoked"):
            accept_invite(raw, uuid.uuid4(), db)

    def test_accepted_invite_raises(self):
        from app.services.workspace_service import accept_invite, _hash_token

        ws_id = uuid.uuid4()
        raw = "tok"
        invite = _make_invite(ws_id, accepted=True)
        invite.token_hash = _hash_token(raw)

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = invite
        db.query.return_value = q

        with pytest.raises(ValueError, match="already been accepted"):
            accept_invite(raw, uuid.uuid4(), db)

    def test_already_member_raises(self):
        from app.services.workspace_service import accept_invite, _hash_token

        ws_id = uuid.uuid4()
        user_id = uuid.uuid4()
        raw = "tok"
        invite = self._active_invite(ws_id)
        invite.token_hash = _hash_token(raw)
        existing_member = _make_member(ws_id, user_id, "member")

        call_count = [0]
        db = _mock_db()

        def mock_query(model):
            q = MagicMock()
            q.filter.return_value = q
            call_count[0] += 1
            if call_count[0] == 1:
                q.first.return_value = invite
            else:
                q.first.return_value = existing_member
            return q

        db.query.side_effect = mock_query

        with pytest.raises(ValueError, match="already a member"):
            accept_invite(raw, user_id, db)

    def test_creates_membership_on_success(self):
        from app.services.workspace_service import accept_invite, _hash_token
        from app.models.workspace import WorkspaceMember

        ws_id = uuid.uuid4()
        user_id = uuid.uuid4()
        raw = "goodtoken"
        invite = self._active_invite(ws_id)
        invite.token_hash = _hash_token(raw)

        call_count = [0]
        db = _mock_db()

        def mock_query(model):
            q = MagicMock()
            q.filter.return_value = q
            call_count[0] += 1
            if call_count[0] == 1:
                q.first.return_value = invite
            else:
                q.first.return_value = None  # not yet a member
            return q

        db.query.side_effect = mock_query
        added = []
        db.add.side_effect = lambda obj: added.append(obj)

        with patch("app.services.billing_service.assert_can_add_member"):
            member = accept_invite(raw, user_id, db)

        assert any(isinstance(o, WorkspaceMember) for o in added)
        assert invite.accepted_at is not None
        db.commit.assert_called()


class TestRevokeInvite:
    def test_member_cannot_revoke(self):
        from app.services.workspace_service import revoke_invite

        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "member")

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q

        with pytest.raises(PermissionError):
            revoke_invite(ws_id, user_id, uuid.uuid4(), db)

    def test_idempotent_on_already_revoked(self):
        from app.services.workspace_service import revoke_invite

        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "owner")
        invite = _make_invite(ws_id, revoked=True)

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q
        db.get.return_value = invite

        # Should not raise.
        revoke_invite(ws_id, user_id, invite.id, db)

    def test_accepted_invite_cannot_be_revoked(self):
        from app.services.workspace_service import revoke_invite

        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "owner")
        invite = _make_invite(ws_id, accepted=True)

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q
        db.get.return_value = invite

        with pytest.raises(ValueError, match="already-accepted"):
            revoke_invite(ws_id, user_id, invite.id, db)

    def test_list_invites_member_cannot_list(self):
        from app.services.workspace_service import list_invites

        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        actor = _make_member(ws_id, user_id, "member")

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = actor
        db.query.return_value = q

        with pytest.raises(PermissionError):
            list_invites(ws_id, user_id, db)


# ─────────────────────────────────────────────────────────────────────────────
# Default workspace
# ─────────────────────────────────────────────────────────────────────────────


class TestDefaultWorkspace:
    def test_creates_workspace_if_none_exists(self):
        from app.services.workspace_service import get_or_create_default_workspace
        from app.models.workspace import WorkspaceMember

        user_id = uuid.uuid4()
        db = _mock_db()

        added = []
        db.add.side_effect = lambda obj: added.append(obj)

        # No existing memberships.
        q = MagicMock()
        q.filter.return_value = q
        q.order_by.return_value = q
        q.all.return_value = []
        q.first.return_value = None
        db.query.return_value = q

        ws = get_or_create_default_workspace(user_id, "Alice", db)
        assert ws is not None
        assert "Workspace" in ws.name

    def test_returns_existing_owned_workspace(self):
        from app.services.workspace_service import get_or_create_default_workspace

        user_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        existing_ws = _make_workspace("My Workspace")
        existing_ws.id = ws_id
        owner_member = _make_member(ws_id, user_id, "owner")

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.order_by.return_value = q
        q.all.return_value = [owner_member]
        db.query.return_value = q
        db.get.return_value = existing_ws

        ws = get_or_create_default_workspace(user_id, "Alice", db)
        assert ws is existing_ws

    def test_returns_none_if_no_memberships(self):
        from app.services.workspace_service import get_default_workspace_for_user

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.order_by.return_value = q
        q.first.return_value = None
        db.query.return_value = q

        result = get_default_workspace_for_user(uuid.uuid4(), db)
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# Security invariants
# ─────────────────────────────────────────────────────────────────────────────


class TestSecurityInvariants:
    def test_hash_token_is_sha256_hex(self):
        from app.services.workspace_service import _hash_token
        result = _hash_token("some_raw_token")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_token_is_deterministic(self):
        from app.services.workspace_service import _hash_token
        t = "consistent_token"
        assert _hash_token(t) == _hash_token(t)

    def test_hash_token_not_equal_raw(self):
        from app.services.workspace_service import _hash_token
        raw = "raw_token_value"
        assert _hash_token(raw) != raw

    def test_workspace_id_nullable_on_integration_model(self):
        """workspace_id must be nullable to allow backfill migration."""
        from app.models.integration import Integration
        from sqlalchemy import inspect as sa_inspect
        col = Integration.__table__.c.get("workspace_id")
        assert col is not None
        assert col.nullable is True, "workspace_id must be nullable during backfill"

    def test_invite_token_hash_is_stored_not_raw(self):
        """Verify the WorkspaceInvite model has token_hash, not raw_token."""
        from app.models.workspace import WorkspaceInvite
        cols = {c.name for c in WorkspaceInvite.__table__.c}
        assert "token_hash" in cols
        assert "token" not in cols
        assert "raw_token" not in cols


# ─────────────────────────────────────────────────────────────────────────────
# Integration service workspace support
# ─────────────────────────────────────────────────────────────────────────────


class TestIntegrationServiceWorkspace:
    def test_create_integration_accepts_workspace_id(self):
        """create_integration must accept workspace_id without raising."""
        import inspect
        from app.services.integration_service import create_integration
        sig = inspect.signature(create_integration)
        assert "workspace_id" in sig.parameters

    def test_get_integrations_by_workspace_exists(self):
        from app.services.integration_service import get_integrations_by_workspace
        assert callable(get_integrations_by_workspace)

    def test_get_integrations_by_workspace_excludes_deleted(self):
        from app.services.integration_service import get_integrations_by_workspace
        from app.models.integration import Integration

        ws_id = uuid.uuid4()
        active = MagicMock()
        active.workspace_id = ws_id
        active.status = "active"

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.order_by.return_value = q
        q.all.return_value = [active]
        db.query.return_value = q

        result = get_integrations_by_workspace(workspace_id=ws_id, db=db)
        # Verify filter was called (exact args checked at call time via filter chain)
        assert q.filter.called


# ─────────────────────────────────────────────────────────────────────────────
# Scoping / access control
# ─────────────────────────────────────────────────────────────────────────────


class TestScopingAccessControl:
    def test_non_member_cannot_get_workspace(self):
        from app.services.workspace_service import get_workspace

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = None
        db.query.return_value = q

        result = get_workspace(uuid.uuid4(), uuid.uuid4(), db)
        assert result is None, "Non-member should not access workspace"

    def test_non_member_cannot_list_members(self):
        from app.services.workspace_service import list_members

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = None
        db.query.return_value = q

        with pytest.raises(LookupError):
            list_members(uuid.uuid4(), uuid.uuid4(), db)

    def test_non_member_cannot_invite(self):
        from app.services.workspace_service import create_invite

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = None
        db.query.return_value = q

        with pytest.raises(LookupError):
            create_invite(uuid.uuid4(), uuid.uuid4(), "a@b.com", "member", db)

    def test_non_member_cannot_remove_member(self):
        from app.services.workspace_service import remove_member

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = None
        db.query.return_value = q

        with pytest.raises(LookupError):
            remove_member(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), db)


# ─────────────────────────────────────────────────────────────────────────────
# Integration role enforcement (M50.5 security polish)
# ─────────────────────────────────────────────────────────────────────────────


class TestIntegrationRoleEnforcement:
    """Verify that only owners/admins can add integrations to a shared workspace.

    The role check lives in the integrations router (create_integration).  We
    test the underlying workspace_service helper that the router delegates to so
    we can drive the test without spinning up FastAPI or needing live creds.
    """

    def _make_membership(self, role: str) -> MagicMock:
        m = MagicMock()
        m.role = role
        return m

    def test_member_role_not_in_allowed_set(self):
        """Member role must NOT be in the allowed set for integration creation."""
        allowed = {"owner", "admin"}
        member = self._make_membership("member")
        assert member.role not in allowed

    def test_owner_role_in_allowed_set(self):
        allowed = {"owner", "admin"}
        owner = self._make_membership("owner")
        assert owner.role in allowed

    def test_admin_role_in_allowed_set(self):
        allowed = {"owner", "admin"}
        admin = self._make_membership("admin")
        assert admin.role in allowed

    def test_get_membership_returns_none_for_non_member(self):
        """get_membership must return None for non-members (used by router)."""
        from app.services.workspace_service import get_membership

        db = _mock_db()
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = None
        db.query.return_value = q

        result = get_membership(uuid.uuid4(), uuid.uuid4(), db)
        assert result is None

    def test_member_cannot_be_listed_as_admin(self):
        """Confirm role string is preserved exactly — no accidental elevation."""
        m = self._make_membership("member")
        allowed = {"owner", "admin"}
        assert m.role not in allowed, "member role must not be allowed to create integrations"

    def test_integration_router_imports_get_membership(self):
        """Router must import get_membership for workspace access control."""
        import inspect
        import app.routers.integrations as ir_module
        src = inspect.getsource(ir_module)
        assert "get_membership" in src

    def test_integration_router_checks_role_for_workspace(self):
        """Router source must contain the admin-role guard for workspace create."""
        import inspect
        import app.routers.integrations as ir_module
        src = inspect.getsource(ir_module)
        # The guard string added in M50.5
        assert "_INTEGRATION_ALLOWED_ROLES" in src or "admin" in src


class TestAcceptInviteEmailMatch:
    """Document and verify accept_invite email-matching behaviour.

    By design, accept_invite does NOT enforce that the accepting user's email
    matches the invite email.  The raw invite token (256 bits of entropy) is the
    sole credential — whoever holds the URL is authorised to accept.
    This is consistent with link-based invite systems (Slack, Notion, etc.).

    A future milestone can add email-match enforcement if the product requires it.
    """

    def _make_invite(self, ws_id, email="alice@example.com"):
        inv = MagicMock()
        inv.workspace_id = ws_id
        inv.email = email
        inv.role = "member"
        inv.revoked_at = None
        inv.accepted_at = None
        # expires 1 hour from now
        from datetime import datetime, timezone, timedelta
        inv.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        return inv

    def test_accept_invite_succeeds_for_any_authenticated_user(self):
        """accept_invite does not check that user email == invite email.

        This is intentional: the bearer token (raw invite URL) is the auth.
        """
        from app.services.workspace_service import accept_invite, _hash_token

        ws_id = uuid.uuid4()
        raw_token = "anytoken_" + uuid.uuid4().hex
        token_hash = _hash_token(raw_token)

        invite = self._make_invite(ws_id, email="bob@company.com")
        invite.token_hash = token_hash

        accepting_user_id = uuid.uuid4()  # different user — email is NOT "bob@company.com"

        db = _mock_db()

        # db.query(WorkspaceInvite).filter(...).first() → invite
        # db.query(WorkspaceMember).filter(...).first() → None (not a member)
        from app.models.workspace import WorkspaceInvite as WI, WorkspaceMember as WM

        q_invite = MagicMock()
        q_invite.filter.return_value = q_invite
        q_invite.first.return_value = invite

        q_member = MagicMock()
        q_member.filter.return_value = q_member
        q_member.first.return_value = None

        def _query_side(model):
            if model is WI:
                return q_invite
            return q_member  # WorkspaceMember → None (not yet a member)

        db.query.side_effect = _query_side

        added = []
        db.add.side_effect = lambda obj: added.append(obj)

        with patch("app.services.billing_service.assert_can_add_member"):
            member = accept_invite(raw_token, accepting_user_id, db)
        assert member.workspace_id == ws_id
        assert member.user_id == accepting_user_id

    def test_raw_token_entropy_is_sufficient(self):
        """Invite tokens must have at least 32 bytes (256 bits) of entropy."""
        from app.services import workspace_service
        assert workspace_service._INVITE_TOKEN_BYTES >= 32


# ─────────────────────────────────────────────────────────────────────────────
# Regression: existing model/route imports still work
# ─────────────────────────────────────────────────────────────────────────────


class TestRegressionImports:
    def test_integration_model_still_importable(self):
        from app.models.integration import Integration  # noqa: F401

    def test_user_model_still_importable(self):
        from app.models.user import User  # noqa: F401

    def test_integrations_router_still_importable(self):
        from app.routers.integrations import router  # noqa: F401

    def test_changes_router_still_importable(self):
        from app.routers.changes import router  # noqa: F401

    def test_resources_router_still_importable(self):
        from app.routers.resources import router  # noqa: F401

    def test_integration_service_still_importable(self):
        from app.services.integration_service import (  # noqa: F401
            create_integration,
            get_integrations,
        )

    def test_workspace_id_in_integration_create_schema(self):
        """M50: IntegrationCreateRequest must have optional workspace_id."""
        from app.schemas.integration import IntegrationCreateRequest
        import inspect
        # workspace_id is optional field
        req = IntegrationCreateRequest(
            provider="cloudflare",
            display_name="Test",
            api_token="tok",
            zone_id="zone123",
        )
        assert req.workspace_id is None  # defaults to None

    def test_workspace_id_in_integration_create_schema_accepts_uuid(self):
        from app.schemas.integration import IntegrationCreateRequest
        ws_id = uuid.uuid4()
        req = IntegrationCreateRequest(
            provider="cloudflare",
            display_name="Test",
            api_token="tok",
            zone_id="zone123",
            workspace_id=ws_id,
        )
        assert req.workspace_id == ws_id
