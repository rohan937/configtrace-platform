"""M57.4 tests — GitHub Provider App Installation Flow (unit / MagicMock).

All tests use MagicMock / patch — no real database required.

Coverage
--------
Group 1 — State token utilities (github_app.py)
  1.  generate_state_token produces a token that verifies
  2.  verify_state_token accepts a valid token
  3.  verify_state_token rejects an expired token
  4.  verify_state_token rejects wrong user_id
  5.  verify_state_token rejects a tampered signature

Group 2 — _require_app_configured (router helper)
  6.  passes when all four env vars are set
  7.  raises HTTP 503 listing the missing var when GITHUB_APP_ID is absent

Group 3 — GET /integrations/github/app/install-url
  8.  503 when app not configured
  9.  200 returns install_url + state
  10. install_url contains GITHUB_APP_SLUG and the state value

Group 4 — GET /integrations/github/app/installation-repos
  11. 503 when app not configured
  12. 400 on invalid state token
  13. 400 on expired state token
  14. 503 on bad private key (decode_private_key raises ValueError)
  15. 502 on GitHub API failure (list_installation_repos raises RuntimeError)
  16. 200 returns repos + installation_id

Group 5 — POST /integrations/github/app/complete
  17. 503 when app not configured
  18. 400 on invalid state token
  19. 502 when installation token minting fails
  20. 400 when repo credential validation fails (AuthenticationError)
  21. 400 on duplicate repo (ValueError from create_github_app_integration)
  22. 201 success — returns integration with connection_method = "github_app"
  23. 201 success — response body never contains credential fields

Group 6 — integration_service helpers
  24. create_github_app_integration — duplicate repo raises ValueError
  25. get_connection_method returns "github_app" for App integration
  26. get_connection_method returns "pat" for PAT integration
  27. get_connection_method returns None for non-GitHub integration

Group 7 — Sync task: GitHub App credential branch
  28. sync_task mints installation token when credential_type == "github_app"
  29. sync_task does NOT mint installation token for PAT credentials
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

# ── Test constants ─────────────────────────────────────────────────────────────

_SECRET = "test-state-secret-m574-xxyyzz1234"
_FAKE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAfakefakefakekey\n"
    "-----END RSA PRIVATE KEY-----\n"
)
_APP_ID = "99999"
_APP_SLUG = "configtrace-test-app"

# ── Helpers ───────────────────────────────────────────────────────────────────


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _mock_user():
    user = MagicMock()
    user.id = _uuid()
    return user


def _settings_patches():
    """Return a list of patch() context managers for GitHub App settings."""
    return [
        patch("app.routers.integrations_github_app.settings") ,
    ]


# ── Group 1: State token utilities ────────────────────────────────────────────


class TestStateTokenUtils:
    """Direct tests of generate_state_token / verify_state_token."""

    def test_generate_and_verify_round_trip(self):
        from app.core.github_app import generate_state_token, verify_state_token

        user_id = str(_uuid())
        token = generate_state_token(user_id, _SECRET)
        payload = verify_state_token(token, user_id, _SECRET)
        assert payload["user_id"] == user_id

    def test_verify_accepts_valid_token(self):
        from app.core.github_app import generate_state_token, verify_state_token

        user_id = str(_uuid())
        token = generate_state_token(user_id, _SECRET)
        # Should not raise
        result = verify_state_token(token, user_id, _SECRET)
        assert isinstance(result, dict)

    def test_verify_rejects_expired_token(self):
        from app.core.github_app import generate_state_token, verify_state_token

        user_id = str(_uuid())
        expired = generate_state_token(user_id, _SECRET, ttl_seconds=-1)
        with pytest.raises(ValueError, match="expired"):
            verify_state_token(expired, user_id, _SECRET)

    def test_verify_rejects_wrong_user_id(self):
        from app.core.github_app import generate_state_token, verify_state_token

        owner_id = str(_uuid())
        attacker_id = str(_uuid())
        token = generate_state_token(owner_id, _SECRET)
        with pytest.raises(ValueError):
            verify_state_token(token, attacker_id, _SECRET)

    def test_verify_rejects_tampered_signature(self):
        from app.core.github_app import generate_state_token, verify_state_token

        user_id = str(_uuid())
        token = generate_state_token(user_id, _SECRET)
        # Corrupt the last few bytes of the signature part
        parts = token.rsplit(".", 1)
        tampered = parts[0] + ".AAAA" if len(parts) == 2 else token + "X"
        with pytest.raises(ValueError):
            verify_state_token(tampered, user_id, _SECRET)


# ── Group 2: _require_app_configured ─────────────────────────────────────────


class TestRequireAppConfigured:
    def test_passes_when_all_vars_set(self):
        from app.routers.integrations_github_app import _require_app_configured
        from fastapi import HTTPException

        mock_settings = MagicMock()
        mock_settings.GITHUB_APP_ID = _APP_ID
        mock_settings.GITHUB_APP_SLUG = _APP_SLUG
        mock_settings.GITHUB_APP_PRIVATE_KEY = _FAKE_PEM
        mock_settings.GITHUB_APP_OAUTH_STATE_SECRET = _SECRET

        with patch("app.routers.integrations_github_app.settings", mock_settings):
            # Should not raise
            _require_app_configured()

    def test_raises_503_when_app_id_missing(self):
        from app.routers.integrations_github_app import _require_app_configured
        from fastapi import HTTPException

        mock_settings = MagicMock()
        mock_settings.GITHUB_APP_ID = None
        mock_settings.GITHUB_APP_SLUG = _APP_SLUG
        mock_settings.GITHUB_APP_PRIVATE_KEY = _FAKE_PEM
        mock_settings.GITHUB_APP_OAUTH_STATE_SECRET = _SECRET

        with patch("app.routers.integrations_github_app.settings", mock_settings):
            with pytest.raises(HTTPException) as exc_info:
                _require_app_configured()
            assert exc_info.value.status_code == 503
            assert "GITHUB_APP_ID" in exc_info.value.detail


# ── Group 3: GET /install-url ─────────────────────────────────────────────────


class TestGetInstallUrlEndpoint:
    def _client_and_user(self):
        from fastapi.testclient import TestClient
        from app.main import app
        from app.core.auth import get_current_user
        from app.database import get_db

        user = _mock_user()
        db = MagicMock()
        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[get_db] = lambda: db
        return TestClient(app), user

    def _cleanup(self):
        from app.main import app
        from app.core.auth import get_current_user
        from app.database import get_db
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)

    def test_returns_503_when_not_configured(self):
        """Default settings have None for all GitHub App vars → 503."""
        client, _ = self._client_and_user()
        try:
            resp = client.get("/integrations/github/app/install-url")
            assert resp.status_code == 503
            assert "GITHUB_APP_ID" in resp.json()["detail"]
        finally:
            self._cleanup()

    def test_returns_200_with_url_and_state(self):
        client, _ = self._client_and_user()
        mock_settings = MagicMock()
        mock_settings.GITHUB_APP_ID = _APP_ID
        mock_settings.GITHUB_APP_SLUG = _APP_SLUG
        mock_settings.GITHUB_APP_PRIVATE_KEY = _FAKE_PEM
        mock_settings.GITHUB_APP_OAUTH_STATE_SECRET = _SECRET
        try:
            with patch("app.routers.integrations_github_app.settings", mock_settings):
                resp = client.get("/integrations/github/app/install-url")
            assert resp.status_code == 200
            body = resp.json()
            assert "install_url" in body
            assert "state" in body
        finally:
            self._cleanup()

    def test_install_url_contains_slug_and_state(self):
        client, _ = self._client_and_user()
        mock_settings = MagicMock()
        mock_settings.GITHUB_APP_ID = _APP_ID
        mock_settings.GITHUB_APP_SLUG = _APP_SLUG
        mock_settings.GITHUB_APP_PRIVATE_KEY = _FAKE_PEM
        mock_settings.GITHUB_APP_OAUTH_STATE_SECRET = _SECRET
        try:
            with patch("app.routers.integrations_github_app.settings", mock_settings):
                resp = client.get("/integrations/github/app/install-url")
            body = resp.json()
            assert _APP_SLUG in body["install_url"]
            assert body["state"] in body["install_url"]
        finally:
            self._cleanup()


# ── Group 4: GET /installation-repos ─────────────────────────────────────────


class TestGetInstallationReposEndpoint:
    def _client_and_user(self):
        from fastapi.testclient import TestClient
        from app.main import app
        from app.core.auth import get_current_user
        from app.database import get_db

        user = _mock_user()
        db = MagicMock()
        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[get_db] = lambda: db
        return TestClient(app), user

    def _cleanup(self):
        from app.main import app
        from app.core.auth import get_current_user
        from app.database import get_db
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)

    def _valid_state(self, user_id: str) -> str:
        from app.core.github_app import generate_state_token
        return generate_state_token(user_id, _SECRET)

    def _mock_settings(self):
        m = MagicMock()
        m.GITHUB_APP_ID = _APP_ID
        m.GITHUB_APP_SLUG = _APP_SLUG
        m.GITHUB_APP_PRIVATE_KEY = _FAKE_PEM
        m.GITHUB_APP_OAUTH_STATE_SECRET = _SECRET
        return m

    def test_returns_503_when_not_configured(self):
        client, user = self._client_and_user()
        try:
            state = self._valid_state(str(user.id))
            resp = client.get(
                "/integrations/github/app/installation-repos",
                params={"installation_id": 12345, "state": state},
            )
            assert resp.status_code == 503
        finally:
            self._cleanup()

    def test_returns_400_on_invalid_state(self):
        client, user = self._client_and_user()
        try:
            with patch("app.routers.integrations_github_app.settings", self._mock_settings()):
                resp = client.get(
                    "/integrations/github/app/installation-repos",
                    params={"installation_id": 12345, "state": "not.a.valid.state"},
                )
            assert resp.status_code == 400
        finally:
            self._cleanup()

    def test_returns_400_on_expired_state(self):
        from app.core.github_app import generate_state_token

        client, user = self._client_and_user()
        try:
            expired_state = generate_state_token(str(user.id), _SECRET, ttl_seconds=-1)
            with patch("app.routers.integrations_github_app.settings", self._mock_settings()):
                resp = client.get(
                    "/integrations/github/app/installation-repos",
                    params={"installation_id": 12345, "state": expired_state},
                )
            assert resp.status_code == 400
            assert "expired" in resp.json()["detail"].lower()
        finally:
            self._cleanup()

    def test_returns_503_on_bad_private_key(self):
        client, user = self._client_and_user()
        bad_settings = self._mock_settings()
        bad_settings.GITHUB_APP_PRIVATE_KEY = "not-a-pem-key"
        try:
            state = self._valid_state(str(user.id))
            with patch("app.routers.integrations_github_app.settings", bad_settings):
                with patch(
                    "app.routers.integrations_github_app.decode_private_key",
                    side_effect=ValueError("could not be parsed"),
                ):
                    resp = client.get(
                        "/integrations/github/app/installation-repos",
                        params={"installation_id": 12345, "state": state},
                    )
            assert resp.status_code == 503
            assert "could not be parsed" in resp.json()["detail"].lower()
        finally:
            self._cleanup()

    def test_returns_502_on_github_api_error(self):
        client, user = self._client_and_user()
        try:
            state = self._valid_state(str(user.id))
            with (
                patch("app.routers.integrations_github_app.settings", self._mock_settings()),
                patch("app.routers.integrations_github_app._get_app_jwt", return_value="fake-jwt"),
                patch(
                    "app.routers.integrations_github_app.list_installation_repos",
                    side_effect=RuntimeError("GitHub returned HTTP 401"),
                ),
            ):
                resp = client.get(
                    "/integrations/github/app/installation-repos",
                    params={"installation_id": 12345, "state": state},
                )
            assert resp.status_code == 502
        finally:
            self._cleanup()

    def test_returns_200_with_repos(self):
        client, user = self._client_and_user()
        fake_repos = [
            {
                "full_name": "testorg/myrepo",
                "owner": "testorg",
                "name": "myrepo",
                "private": False,
                "description": "A test repo",
            }
        ]
        try:
            state = self._valid_state(str(user.id))
            with (
                patch("app.routers.integrations_github_app.settings", self._mock_settings()),
                patch("app.routers.integrations_github_app._get_app_jwt", return_value="fake-jwt"),
                patch(
                    "app.routers.integrations_github_app.list_installation_repos",
                    return_value=fake_repos,
                ),
            ):
                resp = client.get(
                    "/integrations/github/app/installation-repos",
                    params={"installation_id": 12345, "state": state},
                )
            assert resp.status_code == 200
            body = resp.json()
            assert body["installation_id"] == 12345
            assert len(body["repos"]) == 1
            assert body["repos"][0]["full_name"] == "testorg/myrepo"
        finally:
            self._cleanup()


# ── Group 5: POST /complete ───────────────────────────────────────────────────


class TestCompleteInstallEndpoint:
    def _client_and_user(self):
        from fastapi.testclient import TestClient
        from app.main import app
        from app.core.auth import get_current_user
        from app.database import get_db

        user = _mock_user()
        db = MagicMock()
        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[get_db] = lambda: db
        return TestClient(app), user, db

    def _cleanup(self):
        from app.main import app
        from app.core.auth import get_current_user
        from app.database import get_db
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)

    def _valid_state(self, user_id: str) -> str:
        from app.core.github_app import generate_state_token
        return generate_state_token(user_id, _SECRET)

    def _mock_settings(self):
        m = MagicMock()
        m.GITHUB_APP_ID = _APP_ID
        m.GITHUB_APP_SLUG = _APP_SLUG
        m.GITHUB_APP_PRIVATE_KEY = _FAKE_PEM
        m.GITHUB_APP_OAUTH_STATE_SECRET = _SECRET
        return m

    def _complete_payload(self, user_id: str) -> dict:
        return {
            "installation_id": 12345,
            "state": self._valid_state(user_id),
            "repo_owner": "testorg",
            "repo_name": "myrepo",
            "display_name": "Test GitHub App Integration",
        }

    def test_returns_503_when_not_configured(self):
        client, user, db = self._client_and_user()
        try:
            resp = client.post(
                "/integrations/github/app/complete",
                json=self._complete_payload(str(user.id)),
            )
            assert resp.status_code == 503
        finally:
            self._cleanup()

    def test_returns_400_on_invalid_state(self):
        client, user, db = self._client_and_user()
        try:
            payload = self._complete_payload(str(user.id))
            payload["state"] = "invalid.state.token"
            with patch("app.routers.integrations_github_app.settings", self._mock_settings()):
                resp = client.post("/integrations/github/app/complete", json=payload)
            assert resp.status_code == 400
        finally:
            self._cleanup()

    def test_returns_502_on_install_token_mint_failure(self):
        client, user, db = self._client_and_user()
        try:
            with (
                patch("app.routers.integrations_github_app.settings", self._mock_settings()),
                patch("app.routers.integrations_github_app._get_app_jwt", return_value="fake-jwt"),
                patch(
                    "app.routers.integrations_github_app.mint_installation_token",
                    side_effect=RuntimeError("GitHub returned HTTP 401"),
                ),
            ):
                resp = client.post(
                    "/integrations/github/app/complete",
                    json=self._complete_payload(str(user.id)),
                )
            assert resp.status_code == 502
        finally:
            self._cleanup()

    def test_returns_400_on_repo_auth_failure(self):
        from app.connectors.exceptions import AuthenticationError

        client, user, db = self._client_and_user()
        try:
            with (
                patch("app.routers.integrations_github_app.settings", self._mock_settings()),
                patch("app.routers.integrations_github_app._get_app_jwt", return_value="fake-jwt"),
                patch(
                    "app.routers.integrations_github_app.mint_installation_token",
                    return_value="install-token",
                ),
                patch(
                    "app.connectors.github.GitHubConnector.validate_credentials",
                    side_effect=AuthenticationError("Bad credentials", status_code=401),
                ),
            ):
                resp = client.post(
                    "/integrations/github/app/complete",
                    json=self._complete_payload(str(user.id)),
                )
            assert resp.status_code == 400
            assert "Authentication failed" in resp.json()["detail"]
        finally:
            self._cleanup()

    def test_returns_400_on_duplicate_repo(self):
        client, user, db = self._client_and_user()
        try:
            with (
                patch("app.routers.integrations_github_app.settings", self._mock_settings()),
                patch("app.routers.integrations_github_app._get_app_jwt", return_value="fake-jwt"),
                patch(
                    "app.routers.integrations_github_app.mint_installation_token",
                    return_value="install-token",
                ),
                patch(
                    "app.connectors.github.GitHubConnector.validate_credentials",
                    return_value=True,
                ),
                patch(
                    "app.routers.integrations_github_app.get_or_create_settings",
                    return_value=MagicMock(
                        default_sync_enabled=False,
                        default_sync_interval_minutes=60,
                    ),
                ),
                patch(
                    "app.routers.integrations_github_app.integration_service.create_github_app_integration",
                    side_effect=ValueError("This GitHub repository is already connected."),
                ),
            ):
                resp = client.post(
                    "/integrations/github/app/complete",
                    json=self._complete_payload(str(user.id)),
                )
            assert resp.status_code == 400
            assert "already connected" in resp.json()["detail"]
        finally:
            self._cleanup()

    def test_returns_201_on_success(self):
        from app.schemas.integration import IntegrationResponse

        client, user, db = self._client_and_user()
        mock_integration = MagicMock()
        mock_integration.id = _uuid()
        mock_integration.provider = "github"
        mock_integration.display_name = "Test GitHub App Integration"
        mock_integration.status = "active"
        mock_integration.scheduled_sync_enabled = False
        mock_integration.sync_interval_minutes = None
        mock_integration.consecutive_failure_count = 0
        mock_integration.last_synced_at = None
        mock_integration.created_at = "2026-01-01T00:00:00Z"
        mock_integration.updated_at = "2026-01-01T00:00:00Z"

        try:
            with (
                patch("app.routers.integrations_github_app.settings", self._mock_settings()),
                patch("app.routers.integrations_github_app._get_app_jwt", return_value="fake-jwt"),
                patch(
                    "app.routers.integrations_github_app.mint_installation_token",
                    return_value="install-token",
                ),
                patch(
                    "app.connectors.github.GitHubConnector.validate_credentials",
                    return_value=True,
                ),
                patch(
                    "app.routers.integrations_github_app.get_or_create_settings",
                    return_value=MagicMock(
                        default_sync_enabled=False,
                        default_sync_interval_minutes=60,
                    ),
                ),
                patch(
                    "app.routers.integrations_github_app.integration_service.create_github_app_integration",
                    return_value=mock_integration,
                ),
                patch(
                    "app.routers.integrations_github_app._build_response",
                    return_value=IntegrationResponse(
                        id=mock_integration.id,
                        provider="github",
                        display_name="Test GitHub App Integration",
                        status="active",
                        connection_method="github_app",
                        last_sync_status=None,
                        last_sync_error=None,
                        last_synced_at=None,
                        consecutive_failure_count=0,
                        needs_attention=False,
                        sync_interval_minutes=None,
                        scheduled_sync_enabled=False,
                        created_at="2026-01-01T00:00:00Z",
                        updated_at="2026-01-01T00:00:00Z",
                    ),
                ),
            ):
                resp = client.post(
                    "/integrations/github/app/complete",
                    json=self._complete_payload(str(user.id)),
                )
            assert resp.status_code == 201
            body = resp.json()
            assert body["provider"] == "github"
            assert body["connection_method"] == "github_app"
        finally:
            self._cleanup()

    def test_response_never_contains_credentials(self):
        """The integration response must not leak installation tokens or private keys."""
        from app.schemas.integration import IntegrationResponse

        client, user, db = self._client_and_user()
        mock_integration = MagicMock()
        mock_integration.id = _uuid()

        try:
            with (
                patch("app.routers.integrations_github_app.settings", self._mock_settings()),
                patch("app.routers.integrations_github_app._get_app_jwt", return_value="fake-jwt"),
                patch(
                    "app.routers.integrations_github_app.mint_installation_token",
                    return_value="super-secret-install-token",
                ),
                patch(
                    "app.connectors.github.GitHubConnector.validate_credentials",
                    return_value=True,
                ),
                patch(
                    "app.routers.integrations_github_app.get_or_create_settings",
                    return_value=MagicMock(
                        default_sync_enabled=False,
                        default_sync_interval_minutes=60,
                    ),
                ),
                patch(
                    "app.routers.integrations_github_app.integration_service.create_github_app_integration",
                    return_value=mock_integration,
                ),
                patch(
                    "app.routers.integrations_github_app._build_response",
                    return_value=IntegrationResponse(
                        id=mock_integration.id,
                        provider="github",
                        display_name="Test GitHub App Integration",
                        status="active",
                        connection_method="github_app",
                        last_sync_status=None,
                        last_sync_error=None,
                        last_synced_at=None,
                        consecutive_failure_count=0,
                        needs_attention=False,
                        sync_interval_minutes=None,
                        scheduled_sync_enabled=False,
                        created_at="2026-01-01T00:00:00Z",
                        updated_at="2026-01-01T00:00:00Z",
                    ),
                ),
            ):
                resp = client.post(
                    "/integrations/github/app/complete",
                    json=self._complete_payload(str(user.id)),
                )
            raw = resp.text
            for secret in ("super-secret-install-token", "fake-jwt", "fakefakefakekey"):
                assert secret not in raw, f"Response leaked secret: {secret!r}"
            for field in ("github_token", "installation_id", "private_key"):
                assert f'"{field}"' not in raw, f"Response contains forbidden field: {field!r}"
        finally:
            self._cleanup()


# ── Group 6: integration_service helpers ──────────────────────────────────────


class TestCreateGitHubAppIntegrationService:
    def test_duplicate_repo_raises_value_error(self):
        """create_github_app_integration raises ValueError when repo already connected."""
        from app.services.integration_service import create_github_app_integration

        db = MagicMock()
        user_id = _uuid()

        # Simulate an existing resource row
        existing_resource = MagicMock()
        db.query.return_value.join.return_value.filter.return_value.first.return_value = (
            existing_resource
        )

        with pytest.raises(ValueError, match="already connected"):
            create_github_app_integration(
                user_id=user_id,
                display_name="My Repo Integration",
                credentials={
                    "credential_type": "github_app",
                    "installation_id": 12345,
                    "repo_owner": "testorg",
                    "repo_name": "myrepo",
                },
                db=db,
            )


class TestGetConnectionMethod:
    def test_returns_github_app_for_app_integration(self):
        from app.services.integration_service import get_connection_method

        integration = MagicMock()
        integration.provider = "github"
        integration.resources = [
            MagicMock(resource_metadata={"connection_method": "github_app"})
        ]
        assert get_connection_method(integration) == "github_app"

    def test_returns_pat_for_pat_integration(self):
        from app.services.integration_service import get_connection_method

        integration = MagicMock()
        integration.provider = "github"
        integration.resources = [
            MagicMock(resource_metadata={"connection_method": "pat"})
        ]
        assert get_connection_method(integration) == "pat"

    def test_returns_pat_for_legacy_github_integration_no_metadata(self):
        """Older integrations without connection_method key default to 'pat'."""
        from app.services.integration_service import get_connection_method

        integration = MagicMock()
        integration.provider = "github"
        integration.resources = [MagicMock(resource_metadata={})]
        assert get_connection_method(integration) == "pat"

    def test_returns_none_for_non_github_integration(self):
        from app.services.integration_service import get_connection_method

        integration = MagicMock()
        integration.provider = "cloudflare"
        assert get_connection_method(integration) is None


# ── Group 7: Sync task — GitHub App credential branch ─────────────────────────


class TestSyncTaskGitHubAppBranch:
    """Unit tests for the GitHub App credential branch in sync_integration.

    We call sync_integration() directly but mock out SessionLocal and all
    external dependencies so no real database or GitHub network calls occur.
    """

    def _make_db_and_integration(self, *, credential_type: str):
        """Return a (db, integration, run_id, integ_id, user_id) tuple with mocks."""
        from app.models.integration import Integration

        run_id = str(_uuid())
        integ_id = str(_uuid())
        user_id = str(_uuid())

        _user_uuid = uuid.UUID(user_id)
        _integ_uuid = uuid.UUID(integ_id)
        _run_uuid = uuid.UUID(run_id)

        # Mock SyncRun
        mock_run = MagicMock()
        mock_run.triggered_by = "manual"
        mock_run.id = _run_uuid

        # Mock Integration
        mock_integration = MagicMock(spec=Integration)
        mock_integration.id = _integ_uuid
        mock_integration.user_id = _user_uuid
        mock_integration.provider = "github"
        mock_integration.display_name = "Test Integration"
        mock_integration.consecutive_failure_count = 0
        mock_integration.resources = []

        # Mock a Resource for this integration
        mock_resource = MagicMock()
        mock_resource.id = _uuid()
        mock_resource.integration_id = _integ_uuid
        mock_resource.is_active = True
        mock_resource.last_snapshot_at = None
        mock_resource.provider_resource_type = "github_repo"
        mock_resource.provider_resource_id = "testorg/myrepo"

        # Mock DB session
        db = MagicMock()
        db.get.side_effect = lambda model, pk: {
            _run_uuid: mock_run,
            _integ_uuid: mock_integration,
        }.get(pk)
        # Resources query: db.query(Resource).filter(...).all() → [mock_resource]
        db.query.return_value.filter.return_value.all.return_value = [mock_resource]

        if credential_type == "github_app":
            creds = {
                "credential_type": "github_app",
                "installation_id": 99999,
                "repo_owner": "testorg",
                "repo_name": "myrepo",
            }
        else:
            creds = {
                "github_token": "github_pat_xyz",
                "repo_owner": "testorg",
                "repo_name": "myrepo",
            }

        return db, mock_integration, run_id, integ_id, user_id, creds

    def test_mints_installation_token_for_github_app_creds(self):
        """When credential_type == 'github_app', sync must mint an installation token."""
        db, integration, run_id, integ_id, user_id, creds = (
            self._make_db_and_integration(credential_type="github_app")
        )

        from app import config as _config

        with (
            patch("app.database.SessionLocal", return_value=db),
            patch("app.workers.sync_task.decrypt_credentials", return_value=creds),
            patch(
                "app.core.github_app.decode_private_key",
                return_value="fake-pem",
            ),
            patch(
                "app.core.github_app.mint_app_jwt",
                return_value="fake-app-jwt",
            ) as mock_jwt,
            patch(
                "app.core.github_app.mint_installation_token",
                return_value="fake-install-token",
            ) as mock_install,
            patch(
                "app.connectors.github.GitHubConnector.fetch",
                return_value=[],
            ) as mock_fetch,
            patch("app.services.sync_service.mark_sync_running"),
            patch("app.services.sync_service.mark_sync_completed"),
            patch("app.services.snapshot_service.get_latest_snapshot", return_value=None),
            patch("app.services.snapshot_service.store_snapshot", return_value=(None, False)),
            patch("app.services.alert_service.dispatch_alerts_for_sync"),
            patch.object(_config.settings, "GITHUB_APP_ID", _APP_ID),
            patch.object(_config.settings, "GITHUB_APP_PRIVATE_KEY", _FAKE_PEM),
        ):
            from app.workers.sync_task import sync_integration
            sync_integration(run_id, integ_id, user_id)

        assert mock_jwt.called, "mint_app_jwt must be called for github_app credentials"
        assert mock_install.called, "mint_installation_token must be called for github_app credentials"
        # The connector must receive the installation token as github_token
        call_args = mock_fetch.call_args
        creds_passed = call_args[0][0] if call_args[0] else call_args[1].get("credentials", {})
        assert creds_passed.get("github_token") == "fake-install-token"

    def test_does_not_mint_token_for_pat_creds(self):
        """When credential_type is absent (PAT), no installation token must be minted."""
        db, integration, run_id, integ_id, user_id, creds = (
            self._make_db_and_integration(credential_type="pat")
        )

        with (
            patch("app.database.SessionLocal", return_value=db),
            patch("app.workers.sync_task.decrypt_credentials", return_value=creds),
            patch(
                "app.core.github_app.mint_installation_token"
            ) as mock_install,
            patch(
                "app.connectors.github.GitHubConnector.fetch",
                return_value=[],
            ),
            patch("app.services.sync_service.mark_sync_running"),
            patch("app.services.sync_service.mark_sync_completed"),
            patch("app.services.snapshot_service.get_latest_snapshot", return_value=None),
            patch("app.services.snapshot_service.store_snapshot", return_value=(None, False)),
            patch("app.services.alert_service.dispatch_alerts_for_sync"),
        ):
            from app.workers.sync_task import sync_integration
            sync_integration(run_id, integ_id, user_id)

        assert not mock_install.called, (
            "mint_installation_token must NOT be called for PAT credentials"
        )
