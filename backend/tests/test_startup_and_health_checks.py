"""Final bug hunt — production startup safety and Redis readiness.

Two gaps found:

1. ``ENCRYPTION_KEY`` had no startup validation. Production could start and
   pass every existing health check while every credential-encrypting
   request (connecting any provider) 500ed, because encryption.py only
   raises when actually exercised, not at boot.
2. ``/health`` and ``/health/db`` never checked Redis. A broker outage —
   which breaks every sync enqueue, manual and scheduled — was invisible
   to both endpoints.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app.main as main_module
from app.config import settings
from app.main import app


class TestProductionStartupValidation:
    def test_missing_encryption_key_blocks_production_startup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)
        with pytest.raises(RuntimeError, match="ENCRYPTION_KEY"):
            main_module._validate_production_config()

    def test_valid_encryption_key_allows_production_startup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(
            settings, "ENCRYPTION_KEY", "1W0Cbrb6MVEIMCm9I+4U6OkBX9gozULnlMqoz6Jnkwc="
        )
        main_module._validate_production_config()  # must not raise

    def test_missing_encryption_key_is_fine_outside_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "ENVIRONMENT", "development")
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)
        main_module._validate_production_config()  # must not raise


class TestRedisHealthCheck:
    def test_health_redis_reports_ok_when_reachable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # conftest's autouse deterministic_dns_stub resolves every hostname
        # (including "localhost") to a public example.com IP for SSRF/
        # DNS-rebinding tests elsewhere. Point it at real loopback here so
        # this test exercises actual connectivity to the local Redis
        # container instead of a bogus off-network address.
        from tests import conftest

        monkeypatch.setitem(conftest._TEST_PRIVATE_HOSTS, "localhost", "127.0.0.1")
        client = TestClient(app)
        resp = client.get("/health/redis")
        assert resp.status_code == 200
        assert resp.json()["redis"] == "connected"

    def test_health_redis_reports_503_when_unreachable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "REDIS_URL", "redis://localhost:1/0")
        client = TestClient(app)
        resp = client.get("/health/redis")
        assert resp.status_code == 503
        assert resp.json()["redis"] == "disconnected"
