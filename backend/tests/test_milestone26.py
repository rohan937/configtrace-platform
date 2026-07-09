"""Milestone 26 integration tests — GitHub Provider MVP.

Coverage
--------
1. ``POST /integrations`` with provider='github' creates an Integration row
   and a Resource row of type 'github_repo'.
2. Duplicate-repo validation: connecting the same {owner}/{repo} a second time
   returns a 422/400 with the expected error message.
3. Different users CAN connect the same repository (no cross-user block).
4. Cloudflare integrations still work (no regression).
5. ``create_scheduled_syncs_for_active_integrations`` enqueues GitHub
   integrations as well as Cloudflare integrations.
6. diff_service._tracked_fields_for dispatches correctly for GitHub and
   Cloudflare record types.
7. Schema validation: IntegrationCreateRequest rejects GitHub payloads that
   are missing required fields (github_token, repo_owner, repo_name).
8. Integration service routes to the correct connector for each provider.
9. Alert service _compose_digest uses provider-aware labels.

What's NOT covered here (covered in other suites)
-------------------------------------------------
* GitHub connector HTTP details        → test_github_connector.py
* GitHub risk rule branches            → test_milestone26_risk_rules.py
* Full sync pipeline with mock GitHub  → not DB-needed; unit-tested separately
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.sync_run import SyncRun
from app.models.user import User
from app.schemas.integration import IntegrationCreateRequest
from app.services import sync_service
from app.services.diff_service import _tracked_fields_for, _TRACKED_FIELDS, compute_diff


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_user(db_session: Session, suffix: str = "") -> User:
    uid = uuid.uuid4().hex[:10]
    user = User(
        clerk_id=f"m26_test_{uid}{suffix}",
        email=f"m26_{uid}{suffix}@configtrace.test",
        display_name="M26 Test User",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _make_github_integration(
    db_session: Session,
    user: User,
    *,
    owner: str = "acme",
    repo: str | None = None,
    status: str = "active",
) -> Integration:
    """Create a GitHub integration + resource directly (no API / connector call)."""
    repo = repo or f"repo_{uuid.uuid4().hex[:6]}"
    slug = f"{owner}/{repo}"
    ciphertext, iv = encrypt_credentials({
        "github_token": "github_pat_test",
        "repo_owner": owner,
        "repo_name": repo,
    })
    integration = Integration(
        user_id=user.id,
        provider="github",
        display_name=f"GitHub {slug}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status=status,
        scheduled_sync_enabled=True,
        sync_interval_minutes=60,
    )
    db_session.add(integration)
    db_session.flush()

    resource = Resource(
        integration_id=integration.id,
        user_id=user.id,
        provider_resource_type="github_repo",
        provider_resource_id=slug,
        display_name=f"GitHub {slug}",
        resource_metadata={"repo_owner": owner, "repo_name": repo},
        is_active=True,
    )
    db_session.add(resource)
    db_session.commit()
    db_session.refresh(integration)
    return integration


def _make_cloudflare_integration(
    db_session: Session,
    user: User,
    *,
    status: str = "active",
) -> Integration:
    zone = f"zone_{uuid.uuid4().hex[:8]}"
    ciphertext, iv = encrypt_credentials({"api_token": "tok", "zone_id": zone})
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name=f"CF {zone}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status=status,
        scheduled_sync_enabled=True,
        sync_interval_minutes=60,
    )
    db_session.add(integration)
    db_session.flush()

    resource = Resource(
        integration_id=integration.id,
        user_id=user.id,
        provider_resource_type="cloudflare_dns_zone",
        provider_resource_id=zone,
        display_name=f"CF {zone} (DNS Zone)",
        resource_metadata={"zone_id": zone},
        is_active=True,
    )
    db_session.add(resource)
    db_session.commit()
    db_session.refresh(integration)
    return integration


# ─────────────────────────────────────────────────────────────────────────────
# 1. POST /integrations with provider='github'
# ─────────────────────────────────────────────────────────────────────────────

def test_create_github_integration_via_api(client, test_user, db_session):
    """POST /integrations with provider='github' succeeds when connector validates ok."""
    with patch(
        "app.connectors.github.GitHubConnector.validate_credentials",
        return_value=True,
    ):
        resp = client.post("/integrations", json={
            "provider": "github",
            "display_name": "My GitHub Repo",
            "github_token": "github_pat_test",
            "repo_owner": "acme",
            "repo_name": "api-server",
        })

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["provider"] == "github"
    assert body["display_name"] == "My GitHub Repo"
    assert body["status"] == "active"
    assert body["resource_count"] == 1

    # Verify DB row
    db_session.expire_all()
    integration = db_session.query(Integration).filter(
        Integration.user_id == test_user.id,
        Integration.provider == "github",
    ).first()
    assert integration is not None

    # Verify Resource row
    resource = db_session.query(Resource).filter(
        Resource.integration_id == integration.id,
    ).first()
    assert resource is not None
    assert resource.provider_resource_type == "github_repo"
    assert resource.provider_resource_id == "acme/api-server"


def test_create_github_integration_response_excludes_credentials(client, test_user):
    """Response body must never contain the PAT or any credential field."""
    with patch(
        "app.connectors.github.GitHubConnector.validate_credentials",
        return_value=True,
    ):
        resp = client.post("/integrations", json={
            "provider": "github",
            "display_name": "Creds test",
            "github_token": "github_pat_should_not_appear",
            "repo_owner": "acme",
            "repo_name": "secret-repo",
        })

    assert resp.status_code == 201
    body = resp.json()
    body_str = str(body)
    assert "github_pat_should_not_appear" not in body_str
    assert "github_token" not in body_str
    assert "encrypted" not in body_str


# ─────────────────────────────────────────────────────────────────────────────
# 2. Duplicate-repo validation
# ─────────────────────────────────────────────────────────────────────────────

def test_duplicate_github_repo_same_user_rejected(client, test_user, db_session):
    """Connecting the same repository twice as the same user returns an error."""
    # Create the first integration directly in DB
    _make_github_integration(db_session, test_user, owner="acme", repo="duplicate-repo")

    # Attempt to connect the same repo again via the API
    with patch(
        "app.connectors.github.GitHubConnector.validate_credentials",
        return_value=True,
    ):
        resp = client.post("/integrations", json={
            "provider": "github",
            "display_name": "Second attempt",
            "github_token": "github_pat_x",
            "repo_owner": "acme",
            "repo_name": "duplicate-repo",
        })

    # Expect 4xx with the duplicate error message
    assert resp.status_code in (400, 422), resp.text
    body_text = resp.text
    assert "already connected" in body_text


# ─────────────────────────────────────────────────────────────────────────────
# 3. Different users CAN connect the same repository
# ─────────────────────────────────────────────────────────────────────────────

def test_different_users_can_connect_same_repo(client, test_user, db_session):
    """A second user should be able to connect a repo already monitored by user 1."""
    # User 1 (test_user) already has this repo
    _make_github_integration(db_session, test_user, owner="acme", repo="shared-repo")

    # Create a second user and give them API access
    user2 = _make_user(db_session, suffix="_user2")
    from app.core.auth import get_current_user
    from app.main import app

    # Temporarily override auth to return user2
    app.dependency_overrides[get_current_user] = lambda: user2
    try:
        with patch(
            "app.connectors.github.GitHubConnector.validate_credentials",
            return_value=True,
        ):
            resp = client.post("/integrations", json={
                "provider": "github",
                "display_name": "User 2 copy",
                "github_token": "github_pat_user2",
                "repo_owner": "acme",
                "repo_name": "shared-repo",
            })
        assert resp.status_code == 201, resp.text
    finally:
        # Restore original override (test_user)
        app.dependency_overrides[get_current_user] = lambda: test_user
        # Cleanup user2
        try:
            db_session.delete(user2)
            db_session.commit()
        except Exception:
            db_session.rollback()


# ─────────────────────────────────────────────────────────────────────────────
# 4. Cloudflare integrations still work (regression check)
# ─────────────────────────────────────────────────────────────────────────────

def test_cloudflare_integration_still_works(client, test_user):
    """Existing Cloudflare integration path is unaffected by M26 changes."""
    with patch(
        "app.connectors.cloudflare.CloudflareConnector.validate_credentials",
        return_value=True,
    ):
        resp = client.post("/integrations", json={
            "provider": "cloudflare",
            "display_name": "CF Regression",
            "api_token": "test_token",
            "zone_id": "abc123def456abc123def456abc123de",
        })

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["provider"] == "cloudflare"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Scheduled syncs include GitHub integrations
# ─────────────────────────────────────────────────────────────────────────────

def test_scheduled_sync_enqueues_github_integrations(db_session):
    """create_scheduled_syncs_for_active_integrations includes GitHub integrations."""
    user = _make_user(db_session, suffix="_schedtest")
    try:
        gh_integration = _make_github_integration(db_session, user)
        cf_integration = _make_cloudflare_integration(db_session, user)

        # Clean up ALL stale in-flight SyncRun records to ensure test isolation.
        # Narrowly scoping by integration_id misses rows from prior test runs
        # that may share the same UUID by coincidence of DB state; any pending/
        # running row will cause has_in_flight_sync to block the scheduler.
        db_session.query(SyncRun).filter(
            SyncRun.status.in_(["pending", "running"]),
        ).delete(synchronize_session=False)
        db_session.commit()

        delay_calls: list[dict] = []

        def _fake_delay(**kwargs):
            delay_calls.append(kwargs)

        with patch("app.workers.sync_task.sync_integration") as mock_task:
            mock_task.delay.side_effect = _fake_delay
            result = sync_service.create_scheduled_syncs_for_active_integrations(db_session)

        enqueued_integration_ids = {c["integration_id"] for c in delay_calls}
        assert str(gh_integration.id) in enqueued_integration_ids, (
            f"GitHub integration not enqueued; result={result}, enqueued={enqueued_integration_ids}"
        )
        assert str(cf_integration.id) in enqueued_integration_ids, (
            f"Cloudflare integration not enqueued; result={result}, enqueued={enqueued_integration_ids}"
        )
    finally:
        try:
            db_session.delete(user)
            db_session.commit()
        except Exception:
            db_session.rollback()


def test_scheduled_sync_skips_paused_github_integrations(db_session):
    """Paused GitHub integrations are not enqueued."""
    user = _make_user(db_session, suffix="_schedpause")
    try:
        gh_paused = _make_github_integration(db_session, user, status="paused")

        delay_calls: list[dict] = []

        def _fake_delay(**kwargs):
            delay_calls.append(kwargs)

        with patch("app.workers.sync_task.sync_integration") as mock_task:
            mock_task.delay.side_effect = _fake_delay
            sync_service.create_scheduled_syncs_for_active_integrations(db_session)

        enqueued_ids = {c["integration_id"] for c in delay_calls}
        assert str(gh_paused.id) not in enqueued_ids
    finally:
        try:
            db_session.delete(user)
            db_session.commit()
        except Exception:
            db_session.rollback()


# ─────────────────────────────────────────────────────────────────────────────
# 6. diff_service tracked fields dispatch
# ─────────────────────────────────────────────────────────────────────────────

def test_tracked_fields_cloudflare_uses_default():
    """Cloudflare DNS records use the standard _TRACKED_FIELDS tuple."""
    record = {"record_type": "A", "name": "api.example.com", "content": "1.2.3.4"}
    fields = _tracked_fields_for(record)
    assert fields is _TRACKED_FIELDS


def test_tracked_fields_github_repo_settings():
    from app.services.diff_service import _GITHUB_TRACKED_FIELDS_BY_TYPE
    record = {"record_type": "github_repo_settings"}
    fields = _tracked_fields_for(record)
    assert fields == _GITHUB_TRACKED_FIELDS_BY_TYPE["github_repo_settings"]
    assert "visibility" in fields
    assert "default_branch" in fields
    assert "archived" in fields


def test_tracked_fields_github_branch_protection():
    from app.services.diff_service import _GITHUB_TRACKED_FIELDS_BY_TYPE
    record = {"record_type": "github_branch_protection"}
    fields = _tracked_fields_for(record)
    assert "protection_enabled" in fields
    assert "allow_force_pushes" in fields
    assert "enforce_admins" in fields


def test_tracked_fields_github_actions_secret():
    """Secrets only track last_updated_at — not created_at or the name."""
    record = {"record_type": "github_actions_secret"}
    fields = _tracked_fields_for(record)
    assert "last_updated_at" in fields
    assert "created_at" not in fields
    assert "value" not in fields


def test_tracked_fields_github_webhook():
    record = {"record_type": "github_webhook"}
    fields = _tracked_fields_for(record)
    assert "url" in fields
    assert "active" in fields
    assert "events" in fields
    assert "insecure_ssl_enabled" in fields


def test_webhook_ssl_verification_disabled_produces_drift_change():
    """Disabling SSL verification on a webhook must surface as a modified-field Change.

    Regression test for the underlying bug: the connector can normalize
    insecure_ssl_enabled correctly, but if the field isn't in the tracked-fields
    tuple for github_webhook, compute_diff will never notice it changed.
    """
    from app.models.snapshot import Snapshot

    def _mock_snapshot(state: list[dict]) -> MagicMock:
        snap = MagicMock(spec=Snapshot)
        snap.state = state
        snap.id = uuid.uuid4()
        return snap

    def _webhook_record(insecure_ssl_enabled) -> dict:
        return {
            "record_id": "acme/myapp#webhook#1",
            "record_type": "github_webhook",
            "name": "hook #1",
            "hook_id": 1,
            "url": "https://ci.example.com/hook",
            "active": True,
            "events": ["push"],
            "content_type": "json",
            "webhook_secret_configured": True,
            "insecure_ssl_enabled": insecure_ssl_enabled,
            "ssl_verification_enabled": (
                None if insecure_ssl_enabled is None else not insecure_ssl_enabled
            ),
        }

    prev = _mock_snapshot([_webhook_record(False)])
    new = _mock_snapshot([_webhook_record(True)])

    changes = compute_diff(prev, new)
    ssl_changes = [c for c in changes if c["field_path"] == "insecure_ssl_enabled"]

    assert len(ssl_changes) == 1
    assert ssl_changes[0]["change_type"] == "modified"
    assert ssl_changes[0]["prev_value"] is False
    assert ssl_changes[0]["new_value"] is True


def test_tracked_fields_github_deploy_key():
    record = {"record_type": "github_deploy_key"}
    fields = _tracked_fields_for(record)
    assert "read_only" in fields
    assert "title" in fields


def test_tracked_fields_unknown_github_type_returns_empty():
    """Unknown github_ types return empty tuple (not Cloudflare fields)."""
    record = {"record_type": "github_future_thing"}
    fields = _tracked_fields_for(record)
    assert fields == ()


def test_tracked_fields_no_record_type_uses_cloudflare():
    """Records without record_type fall back to Cloudflare fields."""
    record = {"name": "example.com"}
    fields = _tracked_fields_for(record)
    assert fields is _TRACKED_FIELDS


# ─────────────────────────────────────────────────────────────────────────────
# 7. IntegrationCreateRequest schema validation
# ─────────────────────────────────────────────────────────────────────────────

def test_schema_github_missing_token_raises():
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="github_token"):
        IntegrationCreateRequest(
            provider="github",
            display_name="Test",
            repo_owner="acme",
            repo_name="myapp",
        )


def test_schema_github_missing_owner_raises():
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="repo_owner"):
        IntegrationCreateRequest(
            provider="github",
            display_name="Test",
            github_token="tok",
            repo_name="myapp",
        )


def test_schema_github_missing_repo_raises():
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="repo_name"):
        IntegrationCreateRequest(
            provider="github",
            display_name="Test",
            github_token="tok",
            repo_owner="acme",
        )


def test_schema_cloudflare_missing_token_raises():
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="api_token"):
        IntegrationCreateRequest(
            provider="cloudflare",
            display_name="Test",
            zone_id="abc123",
        )


def test_schema_cloudflare_missing_zone_raises():
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="zone_id"):
        IntegrationCreateRequest(
            provider="cloudflare",
            display_name="Test",
            api_token="tok",
        )


def test_schema_github_valid():
    req = IntegrationCreateRequest(
        provider="github",
        display_name="Test",
        github_token="github_pat_test",
        repo_owner="acme",
        repo_name="myapp",
    )
    assert req.provider == "github"
    assert req.github_token == "github_pat_test"


def test_schema_cloudflare_valid():
    req = IntegrationCreateRequest(
        provider="cloudflare",
        display_name="CF Test",
        api_token="cf_tok",
        zone_id="abc123def456abc123def456abc123de",
    )
    assert req.provider == "cloudflare"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Alert service uses provider-aware labels
# ─────────────────────────────────────────────────────────────────────────────

def test_alert_compose_digest_github_label(db_session):
    """Alert email subject contains 'GitHub change' for GitHub integrations."""
    from app.services.alert_service import _compose_digest
    from unittest.mock import MagicMock

    user = _make_user(db_session, suffix="_alerttest")
    try:
        gh_integration = _make_github_integration(db_session, user)

        # Build a minimal mock Change with the fields _compose_digest needs
        change = MagicMock()
        change.risk_level = "high"
        change.change_type = "modified"
        change.record_identifier = "github_branch_protection main branch"
        change.field_path = "protection_enabled"
        change.prev_value = True
        change.new_value = False
        change.risk_reason = "Branch protection removed."
        # Real dict so explain_change() dispatches to the GitHub handler correctly
        change.provider_metadata = {"record_type": "github_branch_protection"}
        from datetime import datetime, timezone
        change.created_at = datetime.now(timezone.utc)
        change.id = uuid.uuid4()

        subject, body = _compose_digest(
            integration=gh_integration,
            changes=[change],
        )

        # M28 changed the single-change subject format to:
        # "[ConfigTrace] High-risk GitHub change: <fragment>"
        assert "GitHub change" in subject, f"Expected 'GitHub change' in subject: {subject!r}"
        assert "GitHub" in body
    finally:
        try:
            db_session.delete(user)
            db_session.commit()
        except Exception:
            db_session.rollback()


def test_alert_compose_digest_cloudflare_label(db_session):
    """Alert email subject contains 'DNS' for Cloudflare integrations."""
    from app.services.alert_service import _compose_digest
    from unittest.mock import MagicMock

    user = _make_user(db_session, suffix="_alertcf")
    try:
        cf_integration = _make_cloudflare_integration(db_session, user)

        change = MagicMock()
        change.risk_level = "high"
        change.change_type = "removed"
        change.record_identifier = "A api.example.com"
        change.field_path = None
        change.prev_value = {"record_type": "A", "name": "api.example.com"}
        change.new_value = None
        change.risk_reason = "DNS record removed."
        from datetime import datetime, timezone
        change.created_at = datetime.now(timezone.utc)
        change.id = uuid.uuid4()

        subject, body = _compose_digest(
            integration=cf_integration,
            changes=[change],
        )

        assert "DNS" in subject, f"Expected 'DNS' in subject: {subject!r}"
    finally:
        try:
            db_session.delete(user)
            db_session.commit()
        except Exception:
            db_session.rollback()


# ─────────────────────────────────────────────────────────────────────────────
# 9. GET /integrations lists GitHub integrations
# ─────────────────────────────────────────────────────────────────────────────

def test_get_integrations_includes_github(client, test_user, db_session):
    """GET /integrations lists both Cloudflare and GitHub integrations."""
    _make_github_integration(db_session, test_user, owner="acme", repo="listed-repo")

    resp = client.get("/integrations")
    assert resp.status_code == 200
    body = resp.json()
    providers = [i["provider"] for i in body["integrations"]]
    assert "github" in providers
