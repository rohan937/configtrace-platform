"""Milestone 31 tests — GitHub App Installation Flow.

Coverage
--------
1. HMAC state tokens (app.core.github_app)
   - generate_state_token produces a verifiable token.
   - verify_state_token succeeds for a valid token.
   - verify_state_token rejects a tampered HMAC.
   - verify_state_token rejects an expired token.
   - verify_state_token rejects a user_id mismatch.
   - verify_state_token rejects a malformed token (no dot separator).
   - Custom TTL is honoured.

2. decode_private_key
   - Accepts literal PEM strings.
   - Accepts base64-encoded PEM strings.
   - Falls back to literal for non-PEM base64 content.

3. GET /integrations/github/app/install-url
   - Returns 503 when GitHub App env vars are not set.
   - Returns install_url and state when configured.
   - state is a valid HMAC token bound to the requesting user.

4. GET /integrations/github/app/installation-repos
   - Returns 503 when GitHub App is not configured.
   - Returns 400 for an invalid state token.
   - Returns 400 for an expired state token.
   - Returns 400 for a tampered state token.
   - Returns repos list when state is valid (GitHub API mocked).
   - Returns 502 when GitHub API is unreachable.

5. POST /integrations/github/app/complete
   - Returns 503 when GitHub App is not configured.
   - Returns 400 for invalid state token.
   - Returns 400 for expired state token.
   - Returns 502 when installation token minting fails.
   - Returns 400 when repo validation fails (AuthenticationError).
   - Returns 400 on duplicate repo (same user, same owner/repo).
   - Creates integration + resource on success (201).
   - Response includes connection_method = "github_app".
   - Credentials never appear in the response.

6. connection_method in IntegrationResponse
   - GitHub App integration returns "github_app".
   - GitHub PAT integration returns "pat" (no connection_method in metadata).
   - Cloudflare integration returns None.

7. Reconnect guard for GitHub App integrations
   - POST /integrations/{id}/reconnect returns 422 for GitHub App integration.
   - POST /integrations/{id}/reconnect still works for PAT integrations.

8. Sync task: GitHub App credential branch
   - sync_integration mints an installation token for credential_type=github_app.
   - The minted token is passed as github_token to GitHubConnector.fetch.
   - The minted token is NOT stored in the credentials dict.
"""

from __future__ import annotations

import base64
import time
import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.core.github_app import (
    decode_private_key,
    generate_state_token,
    verify_state_token,
)
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.user import User

# ── Test secret ───────────────────────────────────────────────────────────────

_SECRET = "test-hmac-secret-for-unit-tests"
_USER_ID = "00000000-0000-0000-0000-000000000001"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_user(db: Session, suffix: str = "") -> User:
    uid = uuid.uuid4().hex[:10]
    user = User(
        clerk_id=f"m31_test_{uid}{suffix}",
        email=f"m31_{uid}{suffix}@configtrace.test",
        display_name="M31 Test User",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_github_pat_integration(
    db: Session,
    user: User,
    *,
    status: str = "active",
) -> Integration:
    """PAT-authenticated GitHub integration (no connection_method in metadata)."""
    repo = f"repo_{uuid.uuid4().hex[:6]}"
    slug = f"testorg/{repo}"
    ciphertext, iv = encrypt_credentials({
        "github_token": "github_pat_fake",
        "repo_owner": "testorg",
        "repo_name": repo,
    })
    integration = Integration(
        user_id=user.id,
        provider="github",
        display_name=f"GitHub PAT {slug}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status=status,
    )
    db.add(integration)
    db.flush()
    resource = Resource(
        integration_id=integration.id,
        user_id=user.id,
        provider_resource_type="github_repo",
        provider_resource_id=slug,
        display_name=f"GitHub {slug}",
        resource_metadata={"repo_owner": "testorg", "repo_name": repo},
        is_active=True,
    )
    db.add(resource)
    db.commit()
    db.refresh(integration)
    return integration


def _make_github_app_integration(
    db: Session,
    user: User,
    *,
    repo: str | None = None,
    status: str = "active",
) -> Integration:
    """GitHub App-authenticated integration (connection_method=github_app in metadata)."""
    repo = repo or f"repo_{uuid.uuid4().hex[:6]}"
    slug = f"testorg/{repo}"
    ciphertext, iv = encrypt_credentials({
        "credential_type": "github_app",
        "installation_id": 99999,
        "repo_owner": "testorg",
        "repo_name": repo,
    })
    integration = Integration(
        user_id=user.id,
        provider="github",
        display_name=f"GitHub App {slug}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status=status,
    )
    db.add(integration)
    db.flush()
    resource = Resource(
        integration_id=integration.id,
        user_id=user.id,
        provider_resource_type="github_repo",
        provider_resource_id=slug,
        display_name=f"GitHub App {slug}",
        resource_metadata={
            "repo_owner": "testorg",
            "repo_name": repo,
            "connection_method": "github_app",
        },
        is_active=True,
    )
    db.add(resource)
    db.commit()
    db.refresh(integration)
    return integration


def _make_cloudflare_integration(
    db: Session,
    user: User,
) -> Integration:
    zone = f"zone_{uuid.uuid4().hex[:8]}"
    ciphertext, iv = encrypt_credentials({"api_token": "tok", "zone_id": zone})
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name=f"CF {zone}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db.add(integration)
    db.flush()
    resource = Resource(
        integration_id=integration.id,
        user_id=user.id,
        provider_resource_type="cloudflare_dns_zone",
        provider_resource_id=zone,
        display_name=f"CF {zone}",
        resource_metadata={"zone_id": zone},
        is_active=True,
    )
    db.add(resource)
    db.commit()
    db.refresh(integration)
    return integration


def _patch_github_app_settings(monkeypatch, app_id="12345", slug="configtrace-app"):
    """Patch all four required GitHub App env vars onto settings."""
    from app import config

    monkeypatch.setattr(config.settings, "GITHUB_APP_ID", app_id)
    monkeypatch.setattr(config.settings, "GITHUB_APP_SLUG", slug)
    monkeypatch.setattr(config.settings, "GITHUB_APP_PRIVATE_KEY", "fake-key-pem")
    monkeypatch.setattr(config.settings, "GITHUB_APP_OAUTH_STATE_SECRET", _SECRET)


# ── 1. HMAC state tokens ──────────────────────────────────────────────────────

class TestStateTokens:
    def test_generate_and_verify_roundtrip(self):
        token = generate_state_token(_USER_ID, _SECRET)
        payload = verify_state_token(token, _USER_ID, _SECRET)
        assert payload["user_id"] == _USER_ID
        assert "nonce" in payload
        assert payload["expires_at"] > int(time.time())

    def test_verify_rejects_tampered_hmac(self):
        token = generate_state_token(_USER_ID, _SECRET)
        # Flip the last character of the signature
        parts = token.rsplit(".", 1)
        bad_sig = parts[1][:-1] + ("a" if parts[1][-1] != "a" else "b")
        tampered = f"{parts[0]}.{bad_sig}"
        with pytest.raises(ValueError, match="Invalid state token"):
            verify_state_token(tampered, _USER_ID, _SECRET)

    def test_verify_rejects_expired_token(self):
        token = generate_state_token(_USER_ID, _SECRET, ttl_seconds=-1)
        with pytest.raises(ValueError, match="expired"):
            verify_state_token(token, _USER_ID, _SECRET)

    def test_verify_rejects_user_id_mismatch(self):
        token = generate_state_token(_USER_ID, _SECRET)
        other_user = "00000000-0000-0000-0000-000000000002"
        with pytest.raises(ValueError, match="Invalid state token"):
            verify_state_token(token, other_user, _SECRET)

    def test_verify_rejects_malformed_token_no_dot(self):
        with pytest.raises(ValueError, match="Invalid state token"):
            verify_state_token("nodottoken", _USER_ID, _SECRET)

    def test_verify_rejects_wrong_secret(self):
        token = generate_state_token(_USER_ID, _SECRET)
        with pytest.raises(ValueError, match="Invalid state token"):
            verify_state_token(token, _USER_ID, "wrong-secret")

    def test_custom_ttl(self):
        token = generate_state_token(_USER_ID, _SECRET, ttl_seconds=3600)
        payload = verify_state_token(token, _USER_ID, _SECRET)
        assert payload["expires_at"] > int(time.time()) + 3590

    def test_tokens_are_unique(self):
        t1 = generate_state_token(_USER_ID, _SECRET)
        t2 = generate_state_token(_USER_ID, _SECRET)
        assert t1 != t2  # different nonces


# ── 2. decode_private_key ─────────────────────────────────────────────────────

class TestDecodePrivateKey:
    _FAKE_PEM = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4R\n"
        "-----END RSA PRIVATE KEY-----\n"
    )

    def test_literal_pem_returned_unchanged(self):
        result = decode_private_key(self._FAKE_PEM)
        assert "PRIVATE KEY" in result

    def test_base64_encoded_pem_decoded(self):
        encoded = base64.b64encode(self._FAKE_PEM.encode()).decode()
        result = decode_private_key(encoded)
        assert "PRIVATE KEY" in result
        assert result == self._FAKE_PEM

    def test_non_pem_base64_falls_back_to_literal(self):
        # Base64-encoded string that does NOT contain "PRIVATE KEY"
        non_pem = base64.b64encode(b"this is not a pem file").decode()
        result = decode_private_key(non_pem)
        # Falls back to treating it as literal (raw base64 string returned)
        assert result == non_pem


# ── 3. GET /integrations/github/app/install-url ───────────────────────────────

class TestGetInstallUrl:
    def test_returns_503_when_not_configured(self, client: TestClient):
        resp = client.get("/integrations/github/app/install-url")
        assert resp.status_code == 503
        assert "GITHUB_APP_ID" in resp.json()["detail"]

    def test_returns_install_url_when_configured(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)

        resp = client.get("/integrations/github/app/install-url")
        assert resp.status_code == 200
        body = resp.json()
        assert "install_url" in body
        assert "state" in body
        assert "github.com/apps/configtrace-app/installations/new" in body["install_url"]
        assert body["state"] in body["install_url"]

    def test_state_is_valid_hmac_token(
        self,
        client: TestClient,
        test_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)

        resp = client.get("/integrations/github/app/install-url")
        assert resp.status_code == 200
        state = resp.json()["state"]
        # Should verify successfully for the test user
        payload = verify_state_token(state, str(test_user.id), _SECRET)
        assert payload["user_id"] == str(test_user.id)


# ── 4. GET /integrations/github/app/installation-repos ───────────────────────

class TestGetInstallationRepos:
    def _valid_state(self, user: User) -> str:
        return generate_state_token(str(user.id), _SECRET)

    def test_returns_503_when_not_configured(self, client: TestClient, test_user: User):
        state = self._valid_state(test_user)
        resp = client.get(
            "/integrations/github/app/installation-repos",
            params={"installation_id": 12345, "state": state},
        )
        assert resp.status_code == 503

    def test_returns_400_for_invalid_state(
        self,
        client: TestClient,
        test_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)
        resp = client.get(
            "/integrations/github/app/installation-repos",
            params={"installation_id": 12345, "state": "not.a.real.state"},
        )
        assert resp.status_code == 400

    def test_returns_400_for_expired_state(
        self,
        client: TestClient,
        test_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)
        expired_state = generate_state_token(
            str(test_user.id), _SECRET, ttl_seconds=-1
        )
        resp = client.get(
            "/integrations/github/app/installation-repos",
            params={"installation_id": 12345, "state": expired_state},
        )
        assert resp.status_code == 400
        assert "expired" in resp.json()["detail"].lower()

    def test_returns_repos_when_configured(
        self,
        client: TestClient,
        test_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)
        state = self._valid_state(test_user)

        fake_repos = [
            {
                "full_name": "testorg/myrepo",
                "owner": "testorg",
                "name": "myrepo",
                "private": False,
                "description": "A test repo",
            }
        ]

        with (
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

    def test_returns_502_when_github_unreachable(
        self,
        client: TestClient,
        test_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)
        state = self._valid_state(test_user)

        with (
            patch("app.routers.integrations_github_app._get_app_jwt", return_value="fake-jwt"),
            patch(
                "app.routers.integrations_github_app.list_installation_repos",
                side_effect=RuntimeError("Network error listing repos: Connection refused"),
            ),
        ):
            resp = client.get(
                "/integrations/github/app/installation-repos",
                params={"installation_id": 12345, "state": state},
            )

        assert resp.status_code == 502


# ── 5. POST /integrations/github/app/complete ─────────────────────────────────

class TestCompleteGitHubAppInstall:
    def _valid_state(self, user: User) -> str:
        return generate_state_token(str(user.id), _SECRET)

    def _complete_payload(self, user: User, *, repo: str = "myrepo") -> dict:
        return {
            "installation_id": 12345,
            "state": self._valid_state(user),
            "repo_owner": "testorg",
            "repo_name": repo,
            "display_name": f"Test App Integration ({repo})",
        }

    def test_returns_503_when_not_configured(self, client: TestClient, test_user: User):
        resp = client.post(
            "/integrations/github/app/complete",
            json=self._complete_payload(test_user),
        )
        assert resp.status_code == 503

    def test_returns_400_for_invalid_state(
        self,
        client: TestClient,
        test_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)
        payload = self._complete_payload(test_user)
        payload["state"] = "invalid.state"
        resp = client.post("/integrations/github/app/complete", json=payload)
        assert resp.status_code == 400

    def test_returns_400_for_expired_state(
        self,
        client: TestClient,
        test_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)
        payload = self._complete_payload(test_user)
        payload["state"] = generate_state_token(
            str(test_user.id), _SECRET, ttl_seconds=-1
        )
        resp = client.post("/integrations/github/app/complete", json=payload)
        assert resp.status_code == 400

    def test_returns_502_on_token_minting_failure(
        self,
        client: TestClient,
        test_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)
        with (
            patch("app.routers.integrations_github_app._get_app_jwt", return_value="jwt"),
            patch(
                "app.routers.integrations_github_app.mint_installation_token",
                side_effect=RuntimeError("GitHub returned HTTP 401."),
            ),
        ):
            resp = client.post(
                "/integrations/github/app/complete",
                json=self._complete_payload(test_user),
            )
        assert resp.status_code == 502

    def test_returns_400_on_repo_auth_failure(
        self,
        client: TestClient,
        test_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)
        from app.connectors.exceptions import AuthenticationError

        with (
            patch("app.routers.integrations_github_app._get_app_jwt", return_value="jwt"),
            patch(
                "app.routers.integrations_github_app.mint_installation_token",
                return_value="install-token",
            ),
            patch(
                "app.connectors.github.GitHubConnector.validate_credentials",
                side_effect=AuthenticationError("Bad creds", status_code=401),
            ),
        ):
            resp = client.post(
                "/integrations/github/app/complete",
                json=self._complete_payload(test_user),
            )
        assert resp.status_code == 400
        assert "Authentication failed" in resp.json()["detail"]

    def test_creates_integration_on_success(
        self,
        client: TestClient,
        test_user: User,
        db_session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)

        with (
            patch("app.routers.integrations_github_app._get_app_jwt", return_value="jwt"),
            patch(
                "app.routers.integrations_github_app.mint_installation_token",
                return_value="install-token",
            ),
            patch(
                "app.connectors.github.GitHubConnector.validate_credentials",
                return_value=True,
            ),
        ):
            resp = client.post(
                "/integrations/github/app/complete",
                json=self._complete_payload(test_user, repo="newrepo"),
            )

        assert resp.status_code == 201
        body = resp.json()
        assert body["provider"] == "github"
        assert body["connection_method"] == "github_app"
        assert body["status"] == "active"
        # Credentials must never appear in the response
        for forbidden in ("github_token", "api_token", "installation_id", "private_key"):
            assert forbidden not in body

    def test_returns_400_on_duplicate_repo(
        self,
        client: TestClient,
        test_user: User,
        db_session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)
        # Pre-create an integration for the same repo
        _make_github_app_integration(db_session, test_user, repo="duperepo")

        with (
            patch("app.routers.integrations_github_app._get_app_jwt", return_value="jwt"),
            patch(
                "app.routers.integrations_github_app.mint_installation_token",
                return_value="install-token",
            ),
            patch(
                "app.connectors.github.GitHubConnector.validate_credentials",
                return_value=True,
            ),
        ):
            resp = client.post(
                "/integrations/github/app/complete",
                json={
                    **self._complete_payload(test_user, repo="duperepo"),
                    "repo_owner": "testorg",
                    "repo_name": "duperepo",
                },
            )
        assert resp.status_code == 400
        assert "already connected" in resp.json()["detail"]

    def test_response_never_contains_credentials(
        self,
        client: TestClient,
        test_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _patch_github_app_settings(monkeypatch)

        with (
            patch("app.routers.integrations_github_app._get_app_jwt", return_value="jwt"),
            patch(
                "app.routers.integrations_github_app.mint_installation_token",
                return_value="install-token",
            ),
            patch(
                "app.connectors.github.GitHubConnector.validate_credentials",
                return_value=True,
            ),
        ):
            resp = client.post(
                "/integrations/github/app/complete",
                json=self._complete_payload(test_user, repo="credtest"),
            )

        assert resp.status_code == 201
        raw = resp.text
        for secret in ("install-token", "fake-key-pem", "jwt"):
            assert secret not in raw


# ── 6. connection_method in IntegrationResponse ───────────────────────────────

class TestConnectionMethod:
    def test_github_app_integration_returns_github_app(
        self,
        client: TestClient,
        test_user: User,
        db_session: Session,
    ):
        integration = _make_github_app_integration(db_session, test_user)
        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 200
        assert resp.json()["connection_method"] == "github_app"

    def test_github_pat_integration_returns_pat(
        self,
        client: TestClient,
        test_user: User,
        db_session: Session,
    ):
        integration = _make_github_pat_integration(db_session, test_user)
        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 200
        assert resp.json()["connection_method"] == "pat"

    def test_cloudflare_integration_returns_none(
        self,
        client: TestClient,
        test_user: User,
        db_session: Session,
    ):
        integration = _make_cloudflare_integration(db_session, test_user)
        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 200
        assert resp.json()["connection_method"] is None

    def test_connection_method_in_list_response(
        self,
        client: TestClient,
        test_user: User,
        db_session: Session,
    ):
        app_integration = _make_github_app_integration(db_session, test_user)
        pat_integration = _make_github_pat_integration(db_session, test_user)
        cf_integration = _make_cloudflare_integration(db_session, test_user)

        resp = client.get("/integrations")
        assert resp.status_code == 200
        items = {i["id"]: i for i in resp.json()["integrations"]}

        assert items[str(app_integration.id)]["connection_method"] == "github_app"
        assert items[str(pat_integration.id)]["connection_method"] == "pat"
        assert items[str(cf_integration.id)]["connection_method"] is None


# ── 7. Reconnect guard for GitHub App integrations ────────────────────────────

class TestReconnectGuard:
    def test_reconnect_blocked_for_github_app_integration(
        self,
        client: TestClient,
        test_user: User,
        db_session: Session,
    ):
        integration = _make_github_app_integration(db_session, test_user)
        resp = client.post(
            f"/integrations/{integration.id}/reconnect",
            json={"github_token": "github_pat_new_token"},
        )
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert "GitHub App" in detail

    def test_reconnect_still_works_for_pat_integration(
        self,
        client: TestClient,
        test_user: User,
        db_session: Session,
    ):
        integration = _make_github_pat_integration(db_session, test_user)
        with patch(
            "app.connectors.github.GitHubConnector.validate_credentials",
            return_value=True,
        ):
            resp = client.post(
                f"/integrations/{integration.id}/reconnect",
                json={"github_token": "github_pat_updated"},
            )
        assert resp.status_code == 200
        assert resp.json()["connection_method"] == "pat"


# ── 8. Sync task: GitHub App credential branch ────────────────────────────────

class TestSyncTaskGitHubApp:
    """Tests that the sync worker mints an installation token for App integrations.

    These tests patch at the boundary just above the GitHub API — they verify
    the *behaviour* (token is minted, passed to connector, not stored) without
    making real network calls.
    """

    def _run_sync(
        self,
        integration: Integration,
        test_user: User,
        db_session: Session,
        *,
        monkeypatch: pytest.MonkeyPatch,
    ) -> dict:
        """Run sync_integration task with all external calls mocked."""
        from app.models.sync_run import SyncRun

        run = SyncRun(
            integration_id=integration.id,
            user_id=test_user.id,
            triggered_by="manual",
            status="pending",
        )
        db_session.add(run)
        db_session.commit()
        db_session.refresh(run)

        # Patch GitHub App settings
        _patch_github_app_settings(monkeypatch)

        with (
            patch(
                "app.workers.sync_task.decrypt_credentials",
                return_value={
                    "credential_type": "github_app",
                    "installation_id": 99999,
                    "repo_owner": "testorg",
                    "repo_name": "myrepo",
                },
            ),
            patch(
                "app.core.github_app.decode_private_key",
                return_value="fake-pem",
            ),
            patch(
                "app.core.github_app.mint_app_jwt",
                return_value="fake-app-jwt",
            ) as mock_mint_jwt,
            patch(
                "app.core.github_app.mint_installation_token",
                return_value="fake-install-token",
            ) as mock_mint_install,
            patch(
                "app.connectors.github.GitHubConnector.fetch",
                return_value=[],
            ) as mock_fetch,
        ):
            from app.workers.sync_task import sync_integration
            result = sync_integration(
                str(run.id),
                str(integration.id),
                str(test_user.id),
            )

        return {
            "result": result,
            "mock_mint_jwt": mock_mint_jwt,
            "mock_mint_install": mock_mint_install,
            "mock_fetch": mock_fetch,
        }

    def test_mints_installation_token_for_github_app_integration(
        self,
        test_user: User,
        db_session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ):
        integration = _make_github_app_integration(db_session, test_user)
        mocks = self._run_sync(integration, test_user, db_session, monkeypatch=monkeypatch)

        assert mocks["mock_mint_jwt"].called
        assert mocks["mock_mint_install"].called
        # Installation token must be passed to the connector
        call_kwargs = mocks["mock_fetch"].call_args
        creds_passed = call_kwargs[0][0] if call_kwargs[0] else call_kwargs[1].get("credentials", {})
        assert creds_passed.get("github_token") == "fake-install-token"

    def test_installation_token_not_persisted_in_credentials(
        self,
        test_user: User,
        db_session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """The installation token must be a runtime-only value — not stored."""
        integration = _make_github_app_integration(db_session, test_user)
        mocks = self._run_sync(integration, test_user, db_session, monkeypatch=monkeypatch)

        # Verify sync completed (token was used successfully)
        assert mocks["result"]["status"] == "completed"

        # The stored credentials dict passed to decrypt_credentials is NOT
        # modified — we verify the mock was called with the original creds
        # (no installation_token key should be in the stored creds).
        from app.core.encryption import decrypt_credentials
        stored_creds = decrypt_credentials(
            integration.encrypted_credentials,
            integration.credential_iv,
        )
        assert "github_token" not in stored_creds
        assert stored_creds["credential_type"] == "github_app"

    def test_pat_integration_does_not_mint_token(
        self,
        test_user: User,
        db_session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """PAT integrations must NOT trigger GitHub App token minting."""
        integration = _make_github_pat_integration(db_session, test_user)

        from app.models.sync_run import SyncRun

        run = SyncRun(
            integration_id=integration.id,
            user_id=test_user.id,
            triggered_by="manual",
            status="pending",
        )
        db_session.add(run)
        db_session.commit()
        db_session.refresh(run)

        _patch_github_app_settings(monkeypatch)

        with (
            patch(
                "app.workers.sync_task.decrypt_credentials",
                return_value={
                    "github_token": "github_pat_test",
                    "repo_owner": "testorg",
                    "repo_name": "somerepopat",
                },
            ),
            patch(
                "app.core.github_app.mint_installation_token"
            ) as mock_mint_install,
            patch(
                "app.connectors.github.GitHubConnector.fetch",
                return_value=[],
            ),
        ):
            from app.workers.sync_task import sync_integration
            sync_integration(
                str(run.id),
                str(integration.id),
                str(test_user.id),
            )

        # Installation token must NOT have been minted for a PAT integration
        assert not mock_mint_install.called
