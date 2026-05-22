"""Milestone 21 tests — Authentication and user isolation.

Covers four guarantees that the auth layer must uphold:

1. **Production fail-closed.**
   When ``ENVIRONMENT=production`` and ``CLERK_JWKS_URL`` is missing, every
   protected route returns 503.  The dev-mode branch must be unreachable.

2. **Token validation in Clerk mode.**
   Missing, malformed, expired, and unknown-kid tokens all return 401.
   A valid token returns 200 and resolves the matching ``User`` row.

3. **Dev-mode preservation.**
   When neither production nor Clerk are configured, the legacy dev-user
   behaviour still works exactly as before (auto-create user, header
   override).

4. **Worker user_id mismatch guard.**
   The Celery task refuses to sync an integration whose ``user_id`` does
   not match the user_id argument it was enqueued with.

These tests **do not** use the shared ``client`` fixture from conftest.py
(that fixture monkey-patches ``get_current_user`` and would mask the auth
logic).  Instead they exercise the dependency directly or via a fresh
``TestClient`` with no overrides.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core import auth as auth_module
from app.core.auth import get_current_user
from app.main import app
from app.models.user import User


# ─────────────────────────────────────────────────────────────────────────────
# RSA keypair helpers (for synthesizing signed JWTs)
# ─────────────────────────────────────────────────────────────────────────────

def _generate_rsa_jwk(kid: str) -> tuple[Any, dict[str, Any]]:
    """Generate an RSA keypair and return ``(private_key_pem, public_jwk_dict)``.

    The JWK dict mimics one entry from Clerk's ``/.well-known/jwks.json``.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Build the JWK in the format python-jose accepts directly.
    public_numbers = private_key.public_key().public_numbers()

    def _b64u_uint(value: int) -> str:
        import base64
        length = (value.bit_length() + 7) // 8
        raw = value.to_bytes(length, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64u_uint(public_numbers.n),
        "e": _b64u_uint(public_numbers.e),
    }
    return private_pem, jwk


def _make_token(
    private_pem: bytes,
    kid: str,
    *,
    sub: str = "user_test_sub",
    email: str = "real@example.com",
    name: str = "Real User",
    extra_claims: dict[str, Any] | None = None,
    exp_offset: int = 3600,
) -> str:
    """Sign a JWT with our test private key and the given ``kid``."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": sub,
        "email": email,
        "name": name,
        "iat": now,
        "exp": now + exp_offset,
    }
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(
        claims,
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def raw_client():
    """``TestClient`` with NO auth dependency override.

    Unlike the shared ``client`` fixture in conftest.py, this one exercises
    the real ``get_current_user`` so we can test the auth layer end-to-end.
    """
    # Defensive: make sure nothing leaked an override from a previous test.
    app.dependency_overrides.clear()
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def reset_jwks_cache():
    """Clear the module-level JWKS cache before and after each test."""
    auth_module._reset_jwks_cache_for_tests()
    yield
    auth_module._reset_jwks_cache_for_tests()


@pytest.fixture
def clerk_keypair():
    """Generate a fresh RSA keypair + JWK for the test."""
    return _generate_rsa_jwk(kid="test-kid-1")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Production fail-closed
# ─────────────────────────────────────────────────────────────────────────────

class TestProductionFailClosed:
    """ENVIRONMENT=production must require Clerk; never fall back to dev mode."""

    def test_missing_jwks_returns_503(
        self,
        raw_client,
        monkeypatch,
        reset_jwks_cache,
    ) -> None:
        """Production with no CLERK_JWKS_URL → 503 on every protected route."""
        from app import config

        monkeypatch.setattr(config.settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(config.settings, "CLERK_JWKS_URL", None)

        # No Authorization header — production guard kicks in BEFORE token check.
        resp = raw_client.get("/integrations")
        assert resp.status_code == 503, resp.text
        assert "not configured" in resp.json()["detail"].lower()

    def test_placeholder_jwks_returns_503(
        self,
        raw_client,
        monkeypatch,
        reset_jwks_cache,
    ) -> None:
        """A placeholder JWKS URL (from .env.example) is treated as unconfigured."""
        from app import config

        monkeypatch.setattr(config.settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(
            config.settings,
            "CLERK_JWKS_URL",
            "https://replace-with-your-clerk-frontend-api/.well-known/jwks.json",
        )

        resp = raw_client.get("/integrations")
        assert resp.status_code == 503, resp.text

    def test_production_never_falls_back_to_dev_user(
        self,
        raw_client,
        monkeypatch,
        reset_jwks_cache,
    ) -> None:
        """Even with X-Dev-User-Email set, production must not accept dev mode."""
        from app import config

        monkeypatch.setattr(config.settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(config.settings, "CLERK_JWKS_URL", None)

        resp = raw_client.get(
            "/integrations",
            headers={"X-Dev-User-Email": "attacker@example.com"},
        )
        # Must be 503, NOT 200 with a dev user.
        assert resp.status_code == 503, resp.text


# ─────────────────────────────────────────────────────────────────────────────
# 2. Token validation (Clerk mode)
# ─────────────────────────────────────────────────────────────────────────────

class TestClerkTokenValidation:
    """Exercise the JWT verification path with a real RS256 keypair."""

    def _enable_clerk_mode(
        self,
        monkeypatch,
        jwk: dict[str, Any],
        *,
        environment: str = "production",
    ) -> None:
        from app import config

        monkeypatch.setattr(config.settings, "ENVIRONMENT", environment)
        monkeypatch.setattr(
            config.settings,
            "CLERK_JWKS_URL",
            "https://example.clerk.accounts.dev/.well-known/jwks.json",
        )

        # Patch the network fetch so we never hit a real endpoint.
        def fake_fetch(url: str) -> dict[str, dict[str, Any]]:
            return {jwk["kid"]: jwk}

        monkeypatch.setattr(auth_module, "_fetch_jwks", fake_fetch)

    def test_missing_authorization_header_returns_401(
        self,
        raw_client,
        monkeypatch,
        reset_jwks_cache,
        clerk_keypair,
    ) -> None:
        _, jwk = clerk_keypair
        self._enable_clerk_mode(monkeypatch, jwk)

        resp = raw_client.get("/integrations")
        assert resp.status_code == 401, resp.text
        assert "missing" in resp.json()["detail"].lower()

    def test_malformed_bearer_returns_401(
        self,
        raw_client,
        monkeypatch,
        reset_jwks_cache,
        clerk_keypair,
    ) -> None:
        _, jwk = clerk_keypair
        self._enable_clerk_mode(monkeypatch, jwk)

        resp = raw_client.get(
            "/integrations",
            headers={"Authorization": "NotBearer something"},
        )
        assert resp.status_code == 401, resp.text

    def test_malformed_token_returns_401(
        self,
        raw_client,
        monkeypatch,
        reset_jwks_cache,
        clerk_keypair,
    ) -> None:
        _, jwk = clerk_keypair
        self._enable_clerk_mode(monkeypatch, jwk)

        resp = raw_client.get(
            "/integrations",
            headers={"Authorization": "Bearer not-a-jwt"},
        )
        assert resp.status_code == 401, resp.text

    def test_expired_token_returns_401(
        self,
        raw_client,
        monkeypatch,
        reset_jwks_cache,
        clerk_keypair,
    ) -> None:
        private_pem, jwk = clerk_keypair
        self._enable_clerk_mode(monkeypatch, jwk)

        token = _make_token(
            private_pem,
            kid=jwk["kid"],
            exp_offset=-60,  # expired one minute ago
        )
        resp = raw_client.get(
            "/integrations",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401, resp.text

    def test_unknown_kid_returns_401(
        self,
        raw_client,
        monkeypatch,
        reset_jwks_cache,
        clerk_keypair,
    ) -> None:
        private_pem, jwk = clerk_keypair
        self._enable_clerk_mode(monkeypatch, jwk)

        # Sign with a kid that doesn't exist in the JWKS we serve.
        token = _make_token(private_pem, kid="bogus-kid")
        resp = raw_client.get(
            "/integrations",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401, resp.text

    def test_signature_from_different_key_returns_401(
        self,
        raw_client,
        monkeypatch,
        reset_jwks_cache,
        clerk_keypair,
    ) -> None:
        _, jwk = clerk_keypair
        self._enable_clerk_mode(monkeypatch, jwk)

        # Sign with a DIFFERENT private key but claim the trusted kid.
        attacker_pem, _ = _generate_rsa_jwk(kid="attacker")
        token = _make_token(attacker_pem, kid=jwk["kid"])

        resp = raw_client.get(
            "/integrations",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401, resp.text

    def test_valid_token_creates_user_and_returns_200(
        self,
        raw_client,
        db_session,
        monkeypatch,
        reset_jwks_cache,
        clerk_keypair,
    ) -> None:
        private_pem, jwk = clerk_keypair
        self._enable_clerk_mode(monkeypatch, jwk)

        sub = f"user_{uuid.uuid4().hex[:12]}"
        email = f"{sub}@example.com"
        token = _make_token(private_pem, kid=jwk["kid"], sub=sub, email=email)

        resp = raw_client.get(
            "/integrations",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, resp.text

        # The dependency must have upserted a User row keyed on the sub claim.
        user = db_session.query(User).filter(User.clerk_id == sub).first()
        assert user is not None
        assert user.email == email

        # Cleanup — the raw_client doesn't use the autouse test_user fixture.
        db_session.delete(user)
        db_session.commit()

    def test_jwks_cache_avoids_repeated_fetches(
        self,
        raw_client,
        db_session,
        monkeypatch,
        reset_jwks_cache,
        clerk_keypair,
    ) -> None:
        """Two consecutive valid requests should only fetch the JWKS once."""
        private_pem, jwk = clerk_keypair
        from app import config

        monkeypatch.setattr(config.settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(
            config.settings,
            "CLERK_JWKS_URL",
            "https://example.clerk.accounts.dev/.well-known/jwks.json",
        )

        fetch_count = {"n": 0}

        def counting_fetch(url: str) -> dict[str, dict[str, Any]]:
            fetch_count["n"] += 1
            return {jwk["kid"]: jwk}

        monkeypatch.setattr(auth_module, "_fetch_jwks", counting_fetch)

        sub = f"user_{uuid.uuid4().hex[:12]}"
        token = _make_token(
            private_pem, kid=jwk["kid"], sub=sub, email=f"{sub}@example.com"
        )

        for _ in range(3):
            resp = raw_client.get(
                "/integrations",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200, resp.text

        assert fetch_count["n"] == 1, (
            f"Expected exactly one JWKS fetch across 3 requests, got "
            f"{fetch_count['n']}"
        )

        # Cleanup
        user = db_session.query(User).filter(User.clerk_id == sub).first()
        if user:
            db_session.delete(user)
            db_session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# 3. Dev mode preservation
# ─────────────────────────────────────────────────────────────────────────────

class TestDevModePreserved:
    """Without production + without Clerk → existing dev behaviour stays intact."""

    def test_dev_mode_returns_default_user(
        self,
        raw_client,
        db_session,
        monkeypatch,
        reset_jwks_cache,
    ) -> None:
        from app import config

        monkeypatch.setattr(config.settings, "ENVIRONMENT", "development")
        monkeypatch.setattr(config.settings, "CLERK_JWKS_URL", None)

        resp = raw_client.get("/integrations")
        assert resp.status_code == 200, resp.text

        # Default dev user must exist.
        user = (
            db_session.query(User)
            .filter(User.clerk_id == "dev_dev_at_configtrace_dot_local")
            .first()
        )
        assert user is not None
        # Leave it — other dev-mode tests share this row.

    def test_dev_mode_email_header_override(
        self,
        raw_client,
        db_session,
        monkeypatch,
        reset_jwks_cache,
    ) -> None:
        from app import config

        monkeypatch.setattr(config.settings, "ENVIRONMENT", "development")
        monkeypatch.setattr(config.settings, "CLERK_JWKS_URL", None)

        custom_email = f"alice_{uuid.uuid4().hex[:6]}@example.com"
        resp = raw_client.get(
            "/integrations",
            headers={"X-Dev-User-Email": custom_email},
        )
        assert resp.status_code == 200

        expected_clerk_id = (
            f"dev_{custom_email.replace('@', '_at_').replace('.', '_dot_')}"
        )
        user = (
            db_session.query(User)
            .filter(User.clerk_id == expected_clerk_id)
            .first()
        )
        assert user is not None
        assert user.email == custom_email

        # Cleanup — this user is only used by this test.
        db_session.delete(user)
        db_session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# 4. Worker user_id mismatch guard
# ─────────────────────────────────────────────────────────────────────────────

class TestWorkerOwnershipGuard:
    """The Celery sync_integration task must refuse cross-user execution."""

    def test_sync_raises_when_user_id_does_not_match(
        self,
        db_session,
        test_user,
    ) -> None:
        """Enqueueing sync_integration with a foreign user_id must raise."""
        from app.core.encryption import encrypt_credentials
        from app.models.integration import Integration
        from app.models.sync_run import SyncRun
        from app.workers.sync_task import sync_integration

        # Create an integration owned by *test_user*.
        ciphertext, iv = encrypt_credentials(
            {"api_token": "tok", "zone_id": "zone_iso"}
        )
        integration = Integration(
            user_id=test_user.id,
            provider="cloudflare",
            display_name="Owner Integration",
            encrypted_credentials=ciphertext,
            credential_iv=iv,
            status="active",
        )
        db_session.add(integration)
        db_session.flush()

        sync_run = SyncRun(
            integration_id=integration.id,
            user_id=test_user.id,
            triggered_by="manual",
            status="pending",
        )
        db_session.add(sync_run)
        db_session.commit()
        db_session.refresh(integration)
        db_session.refresh(sync_run)

        # Attempt to execute the task as if a DIFFERENT user enqueued it.
        attacker_user_id = uuid.uuid4()
        assert attacker_user_id != test_user.id

        # Celery .apply() runs the task synchronously in-process — perfect for
        # exercising the guard without needing a worker process.
        result = sync_integration.apply(
            args=[
                str(sync_run.id),
                str(integration.id),
                str(attacker_user_id),
            ]
        )
        # The task is configured with max_retries=0 and re-raises after
        # marking the SyncRun failed.  Celery surfaces the exception.
        assert result.failed(), "sync_integration must fail on user_id mismatch"
        assert isinstance(result.result, ValueError)
        assert "mismatch" in str(result.result).lower()

        # The SyncRun should have been marked failed before the re-raise.
        db_session.refresh(sync_run)
        assert sync_run.status == "failed"
