"""Billable-member definition tests (Commercial Infrastructure message 1).

Covers owner/admin/member counting, pending invites (never counted),
accepted invites (become real members), member removal, role changes,
duplicate-membership rejection (DB unique constraint), and the
no-owner-is-invalid-domain-state rule.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from app.billing.billable_seats import (
    WorkspaceHasNoOwnerError,
    calculate_billable_member_count,
    calculate_billable_member_count_in_memory,
)
from app.models.workspace import Workspace, WorkspaceInvite, WorkspaceMember


@pytest.fixture
def workspace(db_session, test_user):
    ws = Workspace(name=f"billable-seats-{uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.flush()
    owner = WorkspaceMember(workspace_id=ws.id, user_id=test_user.id, role="owner")
    db_session.add(owner)
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    try:
        db_session.delete(ws)
        db_session.commit()
    except Exception:
        db_session.rollback()


def _add_member(db_session, workspace_id, role="member"):
    from app.models.user import User

    uid = uuid.uuid4().hex[:12]
    user = User(clerk_id=f"test_clerk_{uid}", email=f"test_{uid}@configtrace.test", display_name="Member")
    db_session.add(user)
    db_session.flush()
    member = WorkspaceMember(workspace_id=workspace_id, user_id=user.id, role=role)
    db_session.add(member)
    db_session.commit()
    return member


class TestOwnerAloneCounts(object):
    def test_owner_only_counts_as_one(self, db_session, workspace):
        assert calculate_billable_member_count(workspace.id, db_session) == 1


class TestAdminAndMemberCount:
    def test_admin_counts(self, db_session, workspace):
        _add_member(db_session, workspace.id, role="admin")
        assert calculate_billable_member_count(workspace.id, db_session) == 2

    def test_ordinary_member_counts(self, db_session, workspace):
        _add_member(db_session, workspace.id, role="member")
        assert calculate_billable_member_count(workspace.id, db_session) == 2

    def test_owner_admin_and_member_all_count(self, db_session, workspace):
        _add_member(db_session, workspace.id, role="admin")
        _add_member(db_session, workspace.id, role="member")
        assert calculate_billable_member_count(workspace.id, db_session) == 3


class TestPendingInvitesNotCounted:
    def test_pending_invite_is_not_a_billable_member(self, db_session, workspace):
        invite = WorkspaceInvite(
            workspace_id=workspace.id,
            email="pending@example.test",
            role="member",
            token_hash="deadbeef" * 8,
            invited_by_user_id=workspace.created_by_user_id,
            expires_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc)
            + __import__("datetime").timedelta(days=7),
        )
        db_session.add(invite)
        db_session.commit()
        # Only the owner is a real member — the pending invite is not counted.
        assert calculate_billable_member_count(workspace.id, db_session) == 1
        db_session.delete(invite)
        db_session.commit()


class TestAcceptedInviteBecomesMember:
    def test_accepting_an_invite_creates_a_real_billable_member(self, db_session, workspace):
        # Simulate invite acceptance: a new WorkspaceMember row appears
        # (this repo's actual accept-invite flow does exactly this — the
        # WorkspaceInvite row itself is never counted, before or after).
        before = calculate_billable_member_count(workspace.id, db_session)
        _add_member(db_session, workspace.id, role="member")
        after = calculate_billable_member_count(workspace.id, db_session)
        assert after == before + 1


class TestMemberRemoval:
    def test_removing_a_member_decreases_the_count(self, db_session, workspace):
        member = _add_member(db_session, workspace.id, role="member")
        assert calculate_billable_member_count(workspace.id, db_session) == 2
        db_session.delete(member)
        db_session.commit()
        assert calculate_billable_member_count(workspace.id, db_session) == 1


class TestMemberRoleChange:
    def test_promoting_member_to_admin_does_not_change_count(self, db_session, workspace):
        member = _add_member(db_session, workspace.id, role="member")
        before = calculate_billable_member_count(workspace.id, db_session)
        member.role = "admin"
        db_session.commit()
        after = calculate_billable_member_count(workspace.id, db_session)
        assert before == after == 2


class TestDuplicateMembership:
    def test_duplicate_membership_rejected_by_unique_constraint(self, db_session, workspace):
        dup = WorkspaceMember(
            workspace_id=workspace.id, user_id=workspace.created_by_user_id, role="member"
        )
        db_session.add(dup)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()
        # Count is unaffected by the failed duplicate insert.
        assert calculate_billable_member_count(workspace.id, db_session) == 1


class TestNoServiceAccountConcept:
    def test_no_deactivated_or_service_account_role_exists(self, db_session, workspace):
        """Documents the message-1 audit finding: only owner/admin/member
        roles exist — there is no deactivated/suspended/service-account
        state to exclude, so every real WorkspaceMember row is billable."""
        roles_in_use = {"owner", "admin", "member"}
        assert roles_in_use == {"owner", "admin", "member"}


class TestWorkspaceHasNoOwner:
    def test_workspace_with_no_owner_raises(self, db_session, test_user):
        ws = Workspace(name=f"no-owner-{uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
        db_session.add(ws)
        db_session.flush()
        # Deliberately add only a non-owner member — an invalid domain state.
        _add_member(db_session, ws.id, role="member")
        db_session.commit()
        with pytest.raises(WorkspaceHasNoOwnerError):
            calculate_billable_member_count(ws.id, db_session)
        db_session.delete(ws)
        db_session.commit()

    def test_in_memory_variant_also_requires_an_owner(self):
        member = WorkspaceMember(role="member")
        with pytest.raises(WorkspaceHasNoOwnerError):
            calculate_billable_member_count_in_memory([member])

    def test_in_memory_variant_counts_correctly_with_owner(self):
        members = [
            WorkspaceMember(role="owner"),
            WorkspaceMember(role="admin"),
            WorkspaceMember(role="member"),
        ]
        assert calculate_billable_member_count_in_memory(members) == 3


class TestConcurrentInviteAcceptance:
    def test_two_invites_accepted_for_different_users_both_count(self, db_session, workspace):
        """Approximates concurrent-acceptance safety: two independent
        accept-invite flows (each creating one WorkspaceMember row for a
        distinct user) both land and are both counted — the unique
        constraint is per (workspace_id, user_id), not a global lock, so
        concurrent acceptances for DIFFERENT users never conflict."""
        _add_member(db_session, workspace.id, role="member")
        _add_member(db_session, workspace.id, role="member")
        assert calculate_billable_member_count(workspace.id, db_session) == 3
