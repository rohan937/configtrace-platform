"""Milestone 7 tests: encryption, integration routes, sync routes, Celery task.

Run with:
    docker compose run --rm api pytest tests/test_milestone7.py -v

All tests use the fixtures from conftest.py (real PostgreSQL + cleanup).
Cloudflare API calls are always mocked — no live network calls are made.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.models.integration import Integration
from app.models.sync_run import SyncRun


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_integration(db_session, user, *, api_token="tok", zone_id="zone123") -> Integration:
    """Insert an Integration directly into the DB (bypasses validation)."""
    from app.core.encryption import encrypt_credentials

    ciphertext, iv = encrypt_credentials({"api_token": api_token, "zone_id": zone_id})
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name="Test Integration",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db_session.add(integration)
    db_session.commit()
    db_session.refresh(integration)
    return integration


def _make_sync_run(db_session, user, integration) -> SyncRun:
    """Insert a pending SyncRun directly into the DB."""
    from app.services.sync_service import create_sync_run

    return create_sync_run(
        user_id=user.id,
        integration_id=integration.id,
        db=db_session,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. Encryption — pure unit tests
# ─────────────────────────────────────────────────────────────────────────────

def test_encrypt_decrypt_roundtrip() -> None:
    """Encrypting then decrypting a credentials dict returns the original."""
    from app.core.encryption import decrypt_credentials, encrypt_credentials

    creds = {"api_token": "cf_token_abc123", "zone_id": "dead0000beef0000"}
    ciphertext, iv = encrypt_credentials(creds)

    assert isinstance(ciphertext, bytes)
    assert isinstance(iv, bytes)
    assert len(iv) == 12          # 96-bit AES-GCM nonce
    assert ciphertext != iv       # sanity

    recovered = decrypt_credentials(ciphertext, iv)
    assert recovered == creds


def test_encrypt_produces_different_iv_each_time() -> None:
    """Each encrypt call must generate a fresh nonce."""
    from app.core.encryption import encrypt_credentials

    creds = {"api_token": "tok", "zone_id": "z1"}
    _, iv1 = encrypt_credentials(creds)
    _, iv2 = encrypt_credentials(creds)
    assert iv1 != iv2


def test_encrypt_missing_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing ENCRYPTION_KEY raises EncryptionKeyError with helpful text."""
    from app import config
    from app.core.encryption import EncryptionKeyError, encrypt_credentials

    monkeypatch.setattr(config.settings, "ENCRYPTION_KEY", None)
    with pytest.raises(EncryptionKeyError, match="not configured"):
        encrypt_credentials({"k": "v"})


def test_encrypt_placeholder_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """The .env.example placeholder value raises EncryptionKeyError."""
    from app import config
    from app.core.encryption import EncryptionKeyError, encrypt_credentials

    monkeypatch.setattr(
        config.settings, "ENCRYPTION_KEY", "replace-with-base64-encoded-32-byte-key"
    )
    with pytest.raises(EncryptionKeyError):
        encrypt_credentials({"k": "v"})


def test_encrypt_wrong_length_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A base64 key that decodes to ≠ 32 bytes raises EncryptionKeyError."""
    import base64

    from app import config
    from app.core.encryption import EncryptionKeyError, encrypt_credentials

    short_key = base64.b64encode(b"only-16-bytes!!!").decode()  # 16 bytes
    monkeypatch.setattr(config.settings, "ENCRYPTION_KEY", short_key)
    with pytest.raises(EncryptionKeyError, match="32 bytes"):
        encrypt_credentials({"k": "v"})


# ─────────────────────────────────────────────────────────────────────────────
# 2. POST /integrations
# ─────────────────────────────────────────────────────────────────────────────

@patch("app.services.integration_service.CloudflareConnector")
def test_create_integration_success(mock_connector_cls, client: TestClient) -> None:
    """Valid credentials → HTTP 201 with safe metadata only."""
    mock_connector_cls.return_value.validate_credentials.return_value = True

    resp = client.post(
        "/integrations",
        json={
            "provider": "cloudflare",
            "display_name": "My Zone",
            "api_token": "fake_token",
            "zone_id": "abc123def456abc7",
        },
    )

    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["provider"] == "cloudflare"
    assert data["display_name"] == "My Zone"
    assert data["status"] == "active"
    assert "id" in data
    assert "created_at" in data

    # Credentials must NEVER appear in the response
    for forbidden in ("encrypted_credentials", "credential_iv", "api_token", "zone_id"):
        assert forbidden not in data, f"Response must not contain {forbidden!r}"


@patch("app.services.integration_service.CloudflareConnector")
def test_create_integration_invalid_token_returns_400(
    mock_connector_cls, client: TestClient
) -> None:
    """Cloudflare rejects the token → HTTP 400 with a clear message."""
    from app.connectors.exceptions import AuthenticationError

    mock_connector_cls.return_value.validate_credentials.side_effect = AuthenticationError(
        "invalid token", status_code=401
    )

    resp = client.post(
        "/integrations",
        json={
            "provider": "cloudflare",
            "display_name": "Bad Zone",
            "api_token": "bad_token",
            "zone_id": "zzz",
        },
    )

    assert resp.status_code == 400
    assert "authentication" in resp.json()["detail"].lower()


@patch("app.services.integration_service.CloudflareConnector")
def test_create_integration_connector_error_returns_400(
    mock_connector_cls, client: TestClient
) -> None:
    """Non-auth Cloudflare API error → HTTP 400."""
    from app.connectors.exceptions import ConnectorError

    mock_connector_cls.return_value.validate_credentials.side_effect = ConnectorError(
        "zone not found", status_code=404
    )

    resp = client.post(
        "/integrations",
        json={
            "provider": "cloudflare",
            "display_name": "Missing Zone",
            "api_token": "tok",
            "zone_id": "nonexistent",
        },
    )

    assert resp.status_code == 400


def test_create_integration_unsupported_provider_returns_422(
    client: TestClient,
) -> None:
    """Submitting a provider not in the Literal enum → validation error 422."""
    resp = client.post(
        "/integrations",
        json={
            "provider": "stripe",  # not allowed in MVP
            "display_name": "Stripe",
            "api_token": "tok",
            "zone_id": "z",
        },
    )
    assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# 3. GET /integrations
# ─────────────────────────────────────────────────────────────────────────────

def test_list_integrations_returns_created_integration(
    client: TestClient, db_session, test_user
) -> None:
    """After creating an integration, GET /integrations returns it."""
    _make_integration(db_session, test_user)

    resp = client.get("/integrations")

    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["integrations"][0]["provider"] == "cloudflare"


def test_list_integrations_never_exposes_credentials(
    client: TestClient, db_session, test_user
) -> None:
    """GET /integrations must not return any credential-related fields."""
    _make_integration(db_session, test_user)

    resp = client.get("/integrations")
    assert resp.status_code == 200

    for integration_data in resp.json()["integrations"]:
        for forbidden in ("encrypted_credentials", "credential_iv", "api_token", "zone_id"):
            assert forbidden not in integration_data, (
                f"Response must not contain {forbidden!r}"
            )


def test_list_integrations_empty_for_new_user(client: TestClient) -> None:
    """A user with no integrations gets an empty list."""
    resp = client.get("/integrations")
    assert resp.status_code == 200
    assert resp.json() == {"integrations": [], "total": 0}


# ─────────────────────────────────────────────────────────────────────────────
# 4. POST /syncs
# ─────────────────────────────────────────────────────────────────────────────

@patch("app.routers.syncs.sync_integration")
def test_create_sync_returns_pending_sync_run(
    mock_task, client: TestClient, db_session, test_user
) -> None:
    """POST /syncs creates a SyncRun with status='pending'."""
    mock_task.delay.return_value = MagicMock()
    integration = _make_integration(db_session, test_user)

    resp = client.post("/syncs", json={"integration_id": str(integration.id)})

    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["status"] == "pending"
    assert data["triggered_by"] == "manual"
    assert data["integration_id"] == str(integration.id)
    assert data["completed_at"] is None
    # Task should have been enqueued exactly once
    mock_task.delay.assert_called_once()


@patch("app.routers.syncs.sync_integration")
def test_create_sync_enqueues_correct_args(
    mock_task, client: TestClient, db_session, test_user
) -> None:
    """The Celery task is called with the correct sync_run_id and integration_id."""
    mock_task.delay.return_value = MagicMock()
    integration = _make_integration(db_session, test_user)

    resp = client.post("/syncs", json={"integration_id": str(integration.id)})
    assert resp.status_code == 201

    _, kwargs = mock_task.delay.call_args
    call_args = mock_task.delay.call_args
    positional = call_args.args if call_args.args else []
    keyword = call_args.kwargs if call_args.kwargs else {}

    # Accept either positional or keyword arguments
    all_args = list(positional) + list(keyword.values())
    assert str(integration.id) in all_args


def test_create_sync_unknown_integration_returns_404(client: TestClient) -> None:
    """Syncing a non-existent integration → HTTP 404."""
    resp = client.post("/syncs", json={"integration_id": str(uuid.uuid4())})
    assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# 5. GET /syncs/{run_id}
# ─────────────────────────────────────────────────────────────────────────────

def test_get_sync_run_returns_correct_status(
    client: TestClient, db_session, test_user
) -> None:
    """GET /syncs/{id} returns the SyncRun for the authenticated user."""
    integration = _make_integration(db_session, test_user)
    sync_run = _make_sync_run(db_session, test_user, integration)

    resp = client.get(f"/syncs/{sync_run.id}")

    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == str(sync_run.id)
    assert data["status"] == "pending"
    assert data["triggered_by"] == "manual"


def test_get_sync_run_unknown_id_returns_404(client: TestClient) -> None:
    """Requesting a non-existent sync run → HTTP 404."""
    resp = client.get(f"/syncs/{uuid.uuid4()}")
    assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# 6. Celery task — lifecycle test
# ─────────────────────────────────────────────────────────────────────────────

def test_sync_task_transitions_to_completed(
    db_session, test_user, monkeypatch: pytest.MonkeyPatch
) -> None:
    """sync_integration task runs to completion and updates SyncRun status."""
    # Skip the artificial delay so the test doesn't take 2 s
    monkeypatch.setattr("app.workers.sync_task.time.sleep", lambda _: None)

    integration = _make_integration(db_session, test_user)
    sync_run = _make_sync_run(db_session, test_user, integration)
    assert sync_run.status == "pending"

    from app.workers.sync_task import sync_integration

    # apply() runs the task synchronously without going through Redis
    result = sync_integration.apply(
        args=[str(sync_run.id), str(integration.id), str(test_user.id)]
    ).get()

    # Reload from DB so we see the task's committed changes
    db_session.expire(sync_run)
    db_session.refresh(sync_run)

    assert sync_run.status == "completed"
    assert sync_run.snapshot_count == 0
    assert sync_run.change_count == 0
    assert sync_run.completed_at is not None
    assert result["status"] == "completed"


def test_sync_task_marks_failed_on_bad_integration(
    db_session, test_user, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the integration is missing, the task marks the SyncRun as failed."""
    monkeypatch.setattr("app.workers.sync_task.time.sleep", lambda _: None)

    # Create a SyncRun that references a non-existent integration
    nonexistent_integration_id = str(uuid.uuid4())
    integration = _make_integration(db_session, test_user)
    sync_run = _make_sync_run(db_session, test_user, integration)

    from app.workers.sync_task import sync_integration

    # The task should NOT raise — it swallows exceptions and marks failed
    with pytest.raises(Exception):
        sync_integration.apply(
            args=[str(sync_run.id), nonexistent_integration_id, str(test_user.id)],
            throw=True,
        ).get()

    db_session.expire(sync_run)
    db_session.refresh(sync_run)
    assert sync_run.status == "failed"
    assert sync_run.error_message is not None
