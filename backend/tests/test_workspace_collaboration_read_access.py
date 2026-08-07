"""Production-readiness audit fix: workspace-membership read access.

Root cause found during audit: GET read paths for changes, resources, sync
runs, and integration sync-triggering were scoped strictly by
``user_id`` (the row's original creator/connector), NOT workspace
membership — unlike the POST review actions and the security-findings
endpoints, which already correctly used workspace membership. In practice
this meant an invited teammate who joined a Team-plan workspace could see
the integrations list (that path was already workspace-scoped) but would
see ZERO changes, ZERO resources, and could not trigger or view syncs for
integrations someone else in the same workspace had connected — directly
undermining the paid Team plan's core premise.

This file proves the fix: a SECOND workspace member (not the original
connecting user) can read the same data the connecting user can, while a
user with NO membership in the workspace still sees nothing (no
regression on cross-workspace isolation). It also proves the pre-existing
legacy fallback (an integration with no workspace_id) still restricts
strictly to its creating user, unchanged.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete as sa_delete

from app.core.encryption import encrypt_credentials
from app.models.change import Change
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.models.sync_run import SyncRun
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMember
from app.services import changes_service, integration_service, resources_service, sync_service


def _make_user(db_session, *, suffix: str) -> User:
    user = User(
        clerk_id=f"test_clerk_wsra_{suffix}",
        email=f"wsra_{suffix}@configtrace.test",
        display_name=f"WSRA {suffix}",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _make_integration(db_session, owner: User, *, workspace_id=None) -> Integration:
    ciphertext, iv = encrypt_credentials({"api_token": "tok", "zone_id": "zone_wsra"})
    integration = Integration(
        user_id=owner.id,
        workspace_id=workspace_id,
        provider="cloudflare",
        display_name="WSRA Integration",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db_session.add(integration)
    db_session.flush()

    resource = Resource(
        integration_id=integration.id,
        user_id=owner.id,
        provider_resource_type="cloudflare_dns_zone",
        provider_resource_id=f"zone_wsra_{uuid.uuid4().hex[:6]}",
        display_name="Zone WSRA",
        is_active=True,
    )
    db_session.add(resource)
    db_session.commit()
    db_session.refresh(integration)
    return integration


def _make_change(db_session, integration: Integration) -> Change:
    resource = (
        db_session.query(Resource).filter(Resource.integration_id == integration.id).first()
    )
    prev = Snapshot(
        resource_id=resource.id, integration_id=integration.id, user_id=integration.user_id,
        state=[], content_hash="prev_" + uuid.uuid4().hex, triggered_by="manual",
    )
    new = Snapshot(
        resource_id=resource.id, integration_id=integration.id, user_id=integration.user_id,
        state=[], content_hash="new_" + uuid.uuid4().hex, triggered_by="manual",
    )
    db_session.add_all([prev, new])
    db_session.commit()

    change = Change(
        resource_id=resource.id, integration_id=integration.id, user_id=integration.user_id,
        prev_snapshot_id=prev.id, new_snapshot_id=new.id,
        change_type="modified", record_identifier="A record: api.example.com",
        field_path="content", prev_value="1.1.1.1", new_value="2.2.2.2",
        risk_level="medium", risk_reason="IP changed.",
    )
    db_session.add(change)
    db_session.commit()
    db_session.refresh(change)
    return change


def _make_sync_run(db_session, integration: Integration, *, triggered_by="scheduled") -> SyncRun:
    run = SyncRun(
        integration_id=integration.id, user_id=integration.user_id,
        status="completed", triggered_by=triggered_by,
    )
    db_session.add(run)
    db_session.commit()
    db_session.refresh(run)
    return run


@pytest.fixture
def scenario(db_session):
    """owner (creates integration + workspace), teammate (member of the
    same workspace, did NOT create the integration), and outsider (member
    of nothing)."""
    owner = _make_user(db_session, suffix=uuid.uuid4().hex[:8])
    teammate = _make_user(db_session, suffix=uuid.uuid4().hex[:8])
    outsider = _make_user(db_session, suffix=uuid.uuid4().hex[:8])

    ws = Workspace(name=f"wsra-ws-{uuid.uuid4().hex[:8]}", created_by_user_id=owner.id)
    db_session.add(ws)
    db_session.flush()
    db_session.add(WorkspaceMember(workspace_id=ws.id, user_id=owner.id, role="owner"))
    db_session.add(WorkspaceMember(workspace_id=ws.id, user_id=teammate.id, role="member"))
    db_session.commit()

    integration = _make_integration(db_session, owner, workspace_id=ws.id)
    change = _make_change(db_session, integration)
    sync_run = _make_sync_run(db_session, integration)

    yield {
        "owner": owner, "teammate": teammate, "outsider": outsider,
        "workspace": ws, "integration": integration, "change": change, "sync_run": sync_run,
    }

    db_session.expire_all()
    db_session.execute(sa_delete(Change).where(Change.integration_id == integration.id))
    db_session.execute(sa_delete(SyncRun).where(SyncRun.integration_id == integration.id))
    db_session.execute(sa_delete(Snapshot).where(Snapshot.integration_id == integration.id))
    db_session.execute(sa_delete(Resource).where(Resource.integration_id == integration.id))
    db_session.execute(sa_delete(Integration).where(Integration.id == integration.id))
    db_session.execute(sa_delete(WorkspaceMember).where(WorkspaceMember.workspace_id == ws.id))
    db_session.execute(sa_delete(Workspace).where(Workspace.id == ws.id))
    db_session.execute(sa_delete(User).where(User.id.in_([owner.id, teammate.id, outsider.id])))
    db_session.commit()


class TestResourcesVisibleToWorkspaceTeammate:
    def test_teammate_sees_resource_in_list(self, db_session, scenario):
        items, total = resources_service.get_resources(user_id=scenario["teammate"].id, db=db_session)
        assert total >= 1
        assert any(r.integration_id == scenario["integration"].id for r in items)

    def test_teammate_can_fetch_resource_by_id(self, db_session, scenario):
        resource = (
            db_session.query(Resource)
            .filter(Resource.integration_id == scenario["integration"].id)
            .first()
        )
        found = resources_service.get_resource_by_id(resource.id, scenario["teammate"].id, db_session)
        assert found is not None
        assert found.id == resource.id

    def test_outsider_does_not_see_resource(self, db_session, scenario):
        items, total = resources_service.get_resources(user_id=scenario["outsider"].id, db=db_session)
        assert not any(r.integration_id == scenario["integration"].id for r in items)

    def test_outsider_cannot_fetch_resource_by_id(self, db_session, scenario):
        resource = (
            db_session.query(Resource)
            .filter(Resource.integration_id == scenario["integration"].id)
            .first()
        )
        found = resources_service.get_resource_by_id(resource.id, scenario["outsider"].id, db_session)
        assert found is None


class TestChangesVisibleToWorkspaceTeammate:
    def test_teammate_sees_change_in_list(self, db_session, scenario):
        items, total = changes_service.get_changes(user_id=scenario["teammate"].id, db=db_session)
        assert any(c.id == scenario["change"].id for c in items)

    def test_teammate_can_fetch_change_by_id(self, db_session, scenario):
        found = changes_service.get_change_by_id(scenario["change"].id, scenario["teammate"].id, db_session)
        assert found is not None

    def test_teammate_sees_change_in_needs_review(self, db_session, scenario):
        items, total = changes_service.get_needs_review_changes(user_id=scenario["teammate"].id, db=db_session)
        assert any(c.id == scenario["change"].id for c in items)

    def test_owner_still_sees_own_change(self, db_session, scenario):
        """Regression guard: fixing teammate access must not break the
        original creator's own visibility."""
        found = changes_service.get_change_by_id(scenario["change"].id, scenario["owner"].id, db_session)
        assert found is not None

    def test_outsider_does_not_see_change(self, db_session, scenario):
        found = changes_service.get_change_by_id(scenario["change"].id, scenario["outsider"].id, db_session)
        assert found is None

    def test_outsider_not_in_change_list(self, db_session, scenario):
        items, total = changes_service.get_changes(user_id=scenario["outsider"].id, db=db_session)
        assert not any(c.id == scenario["change"].id for c in items)


class TestSyncRunsVisibleToWorkspaceTeammate:
    def test_teammate_can_poll_sync_run(self, db_session, scenario):
        found = sync_service.get_sync_run(
            user_id=scenario["teammate"].id, sync_run_id=scenario["sync_run"].id, db=db_session,
        )
        assert found is not None

    def test_teammate_sees_sync_run_in_integration_history(self, db_session, scenario):
        runs, total = integration_service.get_recent_sync_runs(
            integration_id=scenario["integration"].id, user_id=scenario["teammate"].id, db=db_session,
        )
        assert any(r.id == scenario["sync_run"].id for r in runs)

    def test_outsider_cannot_poll_sync_run(self, db_session, scenario):
        found = sync_service.get_sync_run(
            user_id=scenario["outsider"].id, sync_run_id=scenario["sync_run"].id, db=db_session,
        )
        assert found is None


class TestIntegrationViewerAndManagerRoles:
    def test_teammate_can_view_integration(self, db_session, scenario):
        found = integration_service.get_integration_for_viewer(
            integration_id=scenario["integration"].id, actor_user_id=scenario["teammate"].id, db=db_session,
        )
        assert found is not None

    def test_plain_member_cannot_manage_integration(self, db_session, scenario):
        """A 'member' (not admin/owner) may view but must NOT be treated as
        able to manage (update/delete/reconnect) — proves the reconnect fix
        used the correct (manager-only) helper, not the broader viewer one."""
        managed = integration_service.get_integration_for_manager(
            integration_id=scenario["integration"].id, actor_user_id=scenario["teammate"].id, db=db_session,
        )
        assert managed is None

    def test_owner_can_manage_integration(self, db_session, scenario):
        managed = integration_service.get_integration_for_manager(
            integration_id=scenario["integration"].id, actor_user_id=scenario["owner"].id, db=db_session,
        )
        assert managed is not None

    def test_outsider_cannot_view_integration(self, db_session, scenario):
        found = integration_service.get_integration_for_viewer(
            integration_id=scenario["integration"].id, actor_user_id=scenario["outsider"].id, db=db_session,
        )
        assert found is None


class TestLegacyNonWorkspaceIntegrationFallbackUnchanged:
    """An integration created before workspace linking (workspace_id IS
    NULL) must still be visible ONLY to its exact creating user — the
    fallback branch must not accidentally broaden access."""

    def test_legacy_integration_visible_only_to_creator(self, db_session):
        owner = _make_user(db_session, suffix=uuid.uuid4().hex[:8])
        other = _make_user(db_session, suffix=uuid.uuid4().hex[:8])
        integration = _make_integration(db_session, owner, workspace_id=None)
        change = _make_change(db_session, integration)

        assert changes_service.get_change_by_id(change.id, owner.id, db_session) is not None
        assert changes_service.get_change_by_id(change.id, other.id, db_session) is None

        resource = (
            db_session.query(Resource).filter(Resource.integration_id == integration.id).first()
        )
        assert resources_service.get_resource_by_id(resource.id, owner.id, db_session) is not None
        assert resources_service.get_resource_by_id(resource.id, other.id, db_session) is None

        db_session.expire_all()
        db_session.execute(sa_delete(Change).where(Change.integration_id == integration.id))
        db_session.execute(sa_delete(Snapshot).where(Snapshot.integration_id == integration.id))
        db_session.execute(sa_delete(Resource).where(Resource.integration_id == integration.id))
        db_session.execute(sa_delete(Integration).where(Integration.id == integration.id))
        db_session.execute(sa_delete(User).where(User.id.in_([owner.id, other.id])))
        db_session.commit()
