"""M59.18 — Real high/critical change Slack/push fanout.

Root cause covered
------------------
Before M59.18 the production notification fanout
(``dispatch_notifications_for_sync``) silently no-opped for every GitHub App
integration because the App creator was the only integration creator in
``integration_service.py`` that didn't set ``Integration.workspace_id``.
``integration.workspace_id`` came back NULL, the dispatcher hit its
``skipped_no_settings`` early-return at the top, and Slack + browser-push
were skipped — while email kept working because email reads
``integration.user_id`` and bypasses the workspace lookup entirely.

This test suite pins the four guarantees that close the bug:

  A.  Creating a GitHub App integration writes ``workspace_id`` from the
      caller (regression on the missing-arg bug).
  B.  When the integration row has ``workspace_id=NULL`` (legacy data
      pre-M59.18), the dispatcher falls back to the user's default
      workspace, finds the settings, and dispatches Slack/push instead of
      silently skipping.
  C.  The fallback also persists ``workspace_id`` back onto the row so
      subsequent syncs are fast and the row self-heals.
  D.  When the user has no workspace at all, the dispatcher returns
      ``skipped_no_settings`` cleanly and logs the reason at INFO level
      (no silent skips).

Out of scope
------------
* Slack message formatting / push payload shape — covered elsewhere.
* The credential-revocation path (M59.14) and the derived-status work
  (M59.15) are independent and are not re-tested here.
"""

from __future__ import annotations

import logging
import uuid
from unittest.mock import patch

import pytest
from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.user import User
from app.models.notification_settings import WorkspaceNotificationSettings


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_workspace_for(user: User, db: Session):
    """Create a minimal workspace owned by *user* and return it."""
    from app.services import workspace_service

    return workspace_service.get_or_create_default_workspace(
        user_id=user.id,
        user_display_name=user.display_name or "M59.18 Test",
        db=db,
    )


def _make_github_app_integration(
    db: Session,
    user: User,
    *,
    workspace_id: uuid.UUID | None,
    owner: str = "acme",
    repo: str = "widgets",
) -> Integration:
    from app.models.resource import Resource

    creds = {
        "credential_type": "github_app",
        "installation_id": 11111,
        "repo_owner": owner,
        "repo_name": repo,
    }
    ciphertext, iv = encrypt_credentials(creds)
    integration = Integration(
        user_id=user.id,
        workspace_id=workspace_id,
        provider="github",
        display_name=f"{owner}/{repo}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db.add(integration)
    db.flush()
    db.add(
        Resource(
            integration_id=integration.id,
            user_id=user.id,
            provider_resource_type="github_repo",
            provider_resource_id=f"{owner}/{repo}",
            display_name=f"{owner}/{repo}",
            resource_metadata={
                "repo_owner": owner,
                "repo_name": repo,
                "connection_method": "github_app",
            },
            is_active=True,
        )
    )
    db.commit()
    db.refresh(integration)
    return integration


class _FakeChange:
    """Duck-typed Change suitable for the notification dispatcher.

    Mirrors the same minimal shape used by the existing
    ``test_slack_app_dispatch_gate.py`` suite — the dispatcher only reads a
    handful of attributes off each change, so we can avoid the full
    Resource → Snapshot → Change construction tree (which has FK
    dependencies that aren't relevant to this milestone)."""

    def __init__(
        self,
        *,
        integration_id: uuid.UUID,
        risk_level: str = "critical",
    ):
        self.id = uuid.uuid4()
        self.integration_id = integration_id
        self.risk_level = risk_level
        self.change_type = "modified"
        self.record_identifier = "acme/widgets webhook"
        self.field_path = "config.url"
        self.risk_reason = "Webhook URL changed from https to http."


def _make_critical_change(_db: Session, _user: User, integration: Integration):
    """Return a duck-typed critical Change for the integration."""
    return _FakeChange(integration_id=integration.id, risk_level="critical")


# ─────────────────────────────────────────────────────────────────────────────
# A. create_github_app_integration writes workspace_id
# ─────────────────────────────────────────────────────────────────────────────


class TestGitHubAppCreatorSetsWorkspaceId:

    def test_A1_workspace_id_persisted_on_new_row(self, test_user, db_session):
        from app.services import integration_service

        workspace = _make_workspace_for(test_user, db_session)

        integration = integration_service.create_github_app_integration(
            user_id=test_user.id,
            workspace_id=workspace.id,
            display_name="acme/widgets",
            credentials={
                "credential_type": "github_app",
                "installation_id": 22222,
                "repo_owner": "acme",
                "repo_name": "widgets",
            },
            db=db_session,
        )
        db_session.refresh(integration)
        assert integration.workspace_id == workspace.id

    def test_A2_omitted_workspace_id_still_creates_row(
        self, test_user, db_session
    ):
        """The parameter is optional so older / call-sites without a workspace
        context still work — but the resulting row has workspace_id=NULL,
        which the fanout fallback handles separately (Group B)."""
        from app.services import integration_service

        integration = integration_service.create_github_app_integration(
            user_id=test_user.id,
            display_name="acme/nws",
            credentials={
                "credential_type": "github_app",
                "installation_id": 33333,
                "repo_owner": "acme",
                "repo_name": "nws",
            },
            db=db_session,
        )
        db_session.refresh(integration)
        assert integration.workspace_id is None  # Documented behaviour.


# ─────────────────────────────────────────────────────────────────────────────
# B. Fanout fallback when integration.workspace_id is NULL
# ─────────────────────────────────────────────────────────────────────────────


class TestDispatchFallsBackToUserWorkspace:

    def _seed_workspace_settings_with_app_slack(
        self,
        db: Session,
        workspace_id: uuid.UUID,
    ) -> WorkspaceNotificationSettings:
        """Create a WorkspaceNotificationSettings row with Slack App
        configured.  The token/IV blobs only need to be non-empty for the
        ``_slack_app_active`` guard to evaluate True — the actual Slack
        call is patched out in the test below."""
        row = WorkspaceNotificationSettings(
            workspace_id=workspace_id,
            slack_enabled=False,
            slack_app_enabled=True,
            slack_bot_token_encrypted=b"x" * 16,
            slack_bot_iv=b"y" * 12,
            slack_channel_id="C0123ABCDE",
            webhook_enabled=False,
            notify_on_risk_level="high_and_critical",
        )
        db.add(row)
        db.commit()
        return row

    def test_B1_null_workspace_id_falls_back_and_dispatches(
        self, test_user, db_session
    ):
        """A GitHub App integration with workspace_id=NULL (the M59.18 bug
        condition) should NOT silently skip — the dispatcher should look
        up the user's default workspace, find its Slack settings, and
        dispatch.  The previously-silent skip is the bug; this test pins
        the fix."""
        from app.services import notification_service

        workspace = _make_workspace_for(test_user, db_session)
        self._seed_workspace_settings_with_app_slack(db_session, workspace.id)

        integration = _make_github_app_integration(
            db_session, test_user, workspace_id=None
        )
        change = _make_critical_change(db_session, test_user, integration)

        # Patch the Slack App send so we don't hit the network.  The patch
        # also lets us assert the dispatch actually fired (vs. the old
        # silent-skip behaviour).
        with (
            patch(
                "app.services.slack_service._decrypt_token",
                return_value="xoxb-fake",
            ),
            patch(
                "app.services.slack_service.dispatch_alert_message"
            ) as mock_dispatch,
            patch(
                "app.services.push_notification_service.dispatch_push_for_sync",
                return_value=0,
            ),
        ):
            result = notification_service.dispatch_notifications_for_sync(
                changes=[change],
                integration=integration,
                sync_run_id=uuid.uuid4(),
                db=db_session,
            )

        assert mock_dispatch.called, (
            "Slack App dispatch should have fired even though the integration "
            "had workspace_id=NULL — fallback to the user's default workspace "
            "must trigger the production fanout."
        )
        assert result["slack_sent"] == 1
        assert result["skipped_no_settings"] is False

    def test_B2_fallback_persists_workspace_id_on_row(
        self, test_user, db_session
    ):
        """After a successful fallback, the integration row should have its
        workspace_id populated so subsequent syncs don't repeat the lookup
        and the row self-heals."""
        from app.services import notification_service

        workspace = _make_workspace_for(test_user, db_session)
        self._seed_workspace_settings_with_app_slack(db_session, workspace.id)

        integration = _make_github_app_integration(
            db_session, test_user, workspace_id=None
        )
        change = _make_critical_change(db_session, test_user, integration)

        with (
            patch("app.services.slack_service._decrypt_token", return_value="x"),
            patch("app.services.slack_service.dispatch_alert_message"),
            patch(
                "app.services.push_notification_service.dispatch_push_for_sync",
                return_value=0,
            ),
        ):
            notification_service.dispatch_notifications_for_sync(
                changes=[change],
                integration=integration,
                sync_run_id=uuid.uuid4(),
                db=db_session,
            )

        db_session.refresh(integration)
        assert integration.workspace_id == workspace.id


# ─────────────────────────────────────────────────────────────────────────────
# C. Skip cases stay loud (no silent skips)
# ─────────────────────────────────────────────────────────────────────────────


class TestSkipsAreLogged:

    def test_C1_no_workspace_for_user_logs_at_info(
        self, test_user, db_session, caplog
    ):
        """When the integration has workspace_id=NULL AND the user has no
        workspace membership, the dispatcher must return
        ``skipped_no_settings=True`` AND log the reason at INFO (not
        silently no-op the way the original bug did)."""
        from app.services import notification_service

        # No workspace for this user — fallback will return None.
        integration = _make_github_app_integration(
            db_session, test_user, workspace_id=None
        )
        change = _make_critical_change(db_session, test_user, integration)

        caplog.set_level(logging.INFO, logger="app.services.notification_service")
        result = notification_service.dispatch_notifications_for_sync(
            changes=[change],
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db_session,
        )

        assert result["skipped_no_settings"] is True
        assert result["slack_sent"] == 0
        assert any(
            "no workspace_id" in rec.getMessage()
            or "no workspace" in rec.getMessage()
            for rec in caplog.records
        ), "Skip reason must be logged at INFO so this kind of silent-skip is visible."

    def test_C2_missing_settings_row_logs_at_info(
        self, test_user, db_session, caplog
    ):
        """When the workspace exists but has no notification settings row
        yet, the skip should be logged at INFO with the workspace id."""
        from app.services import notification_service

        workspace = _make_workspace_for(test_user, db_session)
        # NB: deliberately do NOT create a WorkspaceNotificationSettings row.
        integration = _make_github_app_integration(
            db_session, test_user, workspace_id=workspace.id
        )
        change = _make_critical_change(db_session, test_user, integration)

        caplog.set_level(logging.INFO, logger="app.services.notification_service")
        result = notification_service.dispatch_notifications_for_sync(
            changes=[change],
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db_session,
        )

        assert result["skipped_no_settings"] is True
        assert any(
            "no notification settings" in rec.getMessage()
            for rec in caplog.records
        ), "Missing-settings skip must be logged at INFO."
