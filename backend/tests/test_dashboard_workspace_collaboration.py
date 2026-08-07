"""Workspace-collaboration-completion milestone: dashboard_service.py.

Follow-up to commit 2bcd639 (which fixed Changes/Resources/sync read
paths). The audit that produced that commit explicitly flagged
dashboard_service.py as the one remaining surface with the SAME bug
class: every dashboard statistic (integration health, resource counts,
change activity, risk distribution, provider distribution, recent
high/critical changes, recent failed syncs) was computed from
``X.user_id == user_id`` alone — the row's original creator — instead of
workspace membership. A correctly-invited Team-workspace member who
didn't personally connect anything saw an all-zero dashboard even after
2bcd639 gave them correct visibility into the underlying Changes and
Resources lists.

This file proves the fix using the exact same three-user scenario
pattern as test_workspace_collaboration_read_access.py: an owner who
connects the integration, a teammate who is a legitimate workspace
member but did not create anything, and an outsider with no access.
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
from app.services import dashboard_service


def _make_user(db_session, *, suffix: str) -> User:
    user = User(
        clerk_id=f"test_clerk_dwc_{suffix}",
        email=f"dwc_{suffix}@configtrace.test",
        display_name=f"DWC {suffix}",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _make_integration(db_session, owner: User, *, workspace_id=None) -> Integration:
    ciphertext, iv = encrypt_credentials({"api_token": "tok", "zone_id": "zone_dwc"})
    integration = Integration(
        user_id=owner.id,
        workspace_id=workspace_id,
        provider="cloudflare",
        display_name="DWC Integration",
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
        provider_resource_id=f"zone_dwc_{uuid.uuid4().hex[:6]}",
        display_name="Zone DWC",
        is_active=True,
    )
    db_session.add(resource)
    db_session.commit()
    db_session.refresh(integration)
    return integration


def _make_change(db_session, integration: Integration, *, risk_level="high") -> Change:
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
        risk_level=risk_level, risk_reason="IP changed.",
    )
    db_session.add(change)
    db_session.commit()
    db_session.refresh(change)
    return change


def _make_failed_sync_run(db_session, integration: Integration) -> SyncRun:
    from datetime import datetime, timezone

    run = SyncRun(
        integration_id=integration.id, user_id=integration.user_id,
        status="failed", triggered_by="scheduled",
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(run)
    db_session.commit()
    db_session.refresh(run)
    return run


@pytest.fixture
def scenario(db_session):
    owner = _make_user(db_session, suffix=uuid.uuid4().hex[:8])
    teammate = _make_user(db_session, suffix=uuid.uuid4().hex[:8])
    outsider = _make_user(db_session, suffix=uuid.uuid4().hex[:8])

    ws = Workspace(name=f"dwc-ws-{uuid.uuid4().hex[:8]}", created_by_user_id=owner.id)
    db_session.add(ws)
    db_session.flush()
    db_session.add(WorkspaceMember(workspace_id=ws.id, user_id=owner.id, role="owner"))
    db_session.add(WorkspaceMember(workspace_id=ws.id, user_id=teammate.id, role="member"))
    db_session.commit()

    integration = _make_integration(db_session, owner, workspace_id=ws.id)
    change = _make_change(db_session, integration, risk_level="critical")
    failed_run = _make_failed_sync_run(db_session, integration)

    # Force the integration into a "recent failure" state so section 7
    # (recent failed syncs) has something to find.
    from datetime import datetime, timezone

    integration.last_failure_at = datetime.now(timezone.utc)
    integration.consecutive_failure_count = 1
    db_session.commit()

    yield {
        "owner": owner, "teammate": teammate, "outsider": outsider,
        "workspace": ws, "integration": integration, "change": change, "failed_run": failed_run,
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


class TestTeammateSeesCorrectDashboardCounts:
    def test_integration_health_counts_workspace_integration(self, db_session, scenario):
        summary = dashboard_service.get_dashboard_summary(scenario["teammate"].id, db_session)
        assert summary.integration_health.total >= 1
        assert summary.integration_health.active >= 1

    def test_resource_counts_include_workspace_resource(self, db_session, scenario):
        summary = dashboard_service.get_dashboard_summary(scenario["teammate"].id, db_session)
        assert summary.resource_counts.total >= 1

    def test_change_activity_includes_workspace_change(self, db_session, scenario):
        summary = dashboard_service.get_dashboard_summary(scenario["teammate"].id, db_session)
        assert summary.change_activity.total >= 1
        assert summary.change_activity.high_critical_last_7d >= 1
        assert summary.change_activity.last_change_at is not None

    def test_risk_distribution_includes_workspace_change(self, db_session, scenario):
        summary = dashboard_service.get_dashboard_summary(scenario["teammate"].id, db_session)
        assert summary.risk_distribution.critical >= 1

    def test_provider_distribution_includes_workspace_provider(self, db_session, scenario):
        summary = dashboard_service.get_dashboard_summary(scenario["teammate"].id, db_session)
        cloudflare_stats = next(
            (p for p in summary.provider_distribution if p.provider == "cloudflare"), None
        )
        assert cloudflare_stats is not None
        assert cloudflare_stats.integration_count >= 1
        assert cloudflare_stats.resource_count >= 1

    def test_recent_high_critical_changes_includes_workspace_change(self, db_session, scenario):
        summary = dashboard_service.get_dashboard_summary(scenario["teammate"].id, db_session)
        assert any(c.id == str(scenario["change"].id) for c in summary.recent_high_critical_changes)
        # Also proves integration_name/provider are resolved (not None)
        # for a teammate who didn't create the integration.
        match = next(c for c in summary.recent_high_critical_changes if c.id == str(scenario["change"].id))
        assert match.integration_name == "DWC Integration"
        assert match.provider == "cloudflare"

    def test_recent_failed_syncs_includes_workspace_integration(self, db_session, scenario):
        summary = dashboard_service.get_dashboard_summary(scenario["teammate"].id, db_session)
        assert any(
            f.integration_id == str(scenario["integration"].id) for f in summary.recent_failed_syncs
        )

    def test_review_queue_includes_workspace_change(self, db_session, scenario):
        """Already fixed by 2bcd639 (changes_service), verified here as
        part of the same end-to-end dashboard response."""
        summary = dashboard_service.get_dashboard_summary(scenario["teammate"].id, db_session)
        assert summary.review_queue.total >= 1
        assert summary.review_queue.critical >= 1

    def test_owner_still_sees_their_own_dashboard(self, db_session, scenario):
        """Regression guard: fixing teammate visibility must not break
        the original creator's own dashboard."""
        summary = dashboard_service.get_dashboard_summary(scenario["owner"].id, db_session)
        assert summary.integration_health.total >= 1
        assert summary.change_activity.total >= 1


class TestOutsiderSeesNothingFromWorkspace:
    def test_outsider_dashboard_excludes_workspace_data(self, db_session, scenario):
        summary = dashboard_service.get_dashboard_summary(scenario["outsider"].id, db_session)
        assert summary.integration_health.total == 0
        assert summary.resource_counts.total == 0
        assert summary.change_activity.total == 0
        assert not any(
            c.id == str(scenario["change"].id) for c in summary.recent_high_critical_changes
        )
        assert not any(
            f.integration_id == str(scenario["integration"].id) for f in summary.recent_failed_syncs
        )


class TestLegacyNonWorkspaceIntegrationDashboardUnchanged:
    """An integration with no workspace_id must still show up ONLY on its
    creator's dashboard — the fallback branch must not broaden access."""

    def test_legacy_integration_visible_only_to_creator(self, db_session):
        owner = _make_user(db_session, suffix=uuid.uuid4().hex[:8])
        other = _make_user(db_session, suffix=uuid.uuid4().hex[:8])
        integration = _make_integration(db_session, owner, workspace_id=None)
        _make_change(db_session, integration, risk_level="high")

        owner_summary = dashboard_service.get_dashboard_summary(owner.id, db_session)
        other_summary = dashboard_service.get_dashboard_summary(other.id, db_session)

        assert owner_summary.integration_health.total >= 1
        assert other_summary.integration_health.total == 0
        assert other_summary.change_activity.total == 0

        db_session.expire_all()
        db_session.execute(sa_delete(Change).where(Change.integration_id == integration.id))
        db_session.execute(sa_delete(Snapshot).where(Snapshot.integration_id == integration.id))
        db_session.execute(sa_delete(Resource).where(Resource.integration_id == integration.id))
        db_session.execute(sa_delete(Integration).where(Integration.id == integration.id))
        db_session.execute(sa_delete(User).where(User.id.in_([owner.id, other.id])))
        db_session.commit()
