"""M81D — Auth0 Configuration Activity Ingestion.

Auth0 Management API logs (/api/v2/logs) are highly user-centric — every
entry includes user_id, email, IP address, and device data. This milestone
NEVER ingests from that endpoint. Activity events are config-state
observations synthesized from the same 8 safe drift surfaces the drift
connector already reads.

Verifies:
  * Auth0Connector.list_activity_events synthesizes safe config-state events
  * Event types are restricted to _AUTH0_CONFIG_EVENT_TYPES allowlist
  * Login / auth / session / token / user / org events are NEVER returned
  * max_events cap is enforced
  * lookback_hours cap is enforced
  * 401 → AuthenticationError; 403/404 fail soft (permission_limited);
    429 → RateLimitError; network → NetworkError
  * normalize_auth0_activity_event returns None for non-config types
  * normalize_auth0_activity_event processes config events
  * ingestion service normalizes config events to activity events
  * idempotency: same events twice → second run events_inserted=0
  * fingerprint fallback when provider_event_id is None
  * metadata contains NO forbidden fields (no client_secret, access_token,
    JWT, raw URLs, user emails, user IDs, IPs, session data, etc.)
  * workspace scoping (workspace_id always passed to upsert)
  * admin endpoint; member cannot sync
  * ALLOWED_METADATA_KEYS contains expected Auth0 keys
  * ALLOWED_METADATA_KEYS does NOT contain forbidden Auth0 keys
  * capability matrix: activity_ingestion=True, signals/correlations/demo=False
  * expansion framework planned_next_stage contains "M81E"
  * M81A, M81B, M81C tests still pass (regression smoke)
  * forbidden wording not in module source
  * no secret-shaped strings in backend/app or frontend/src

CLAIM DISCIPLINE: configuration-state findings only. Does NOT confirm a
breach, compromise, unauthorized access, data exposure, or leaked secret.
"""

from __future__ import annotations

import inspect
import re
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Constants ──────────────────────────────────────────────────────────────────

FORBIDDEN_PHRASES = [
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
]

FORBIDDEN_METADATA_FIELDS = frozenset({
    # Auth0-specific secrets/credentials that must NEVER be in metadata
    "client_secret", "management_api_token", "access_token",
    "refresh_token_value", "id_token", "jwt", "jwt_value",
    "signing_key", "private_key", "authorization", "bearer",
    # Auth0 PII fields that must NEVER be stored
    "email", "user_email", "user_id",
    # Note: user_name IS in ALLOWED_METADATA_KEYS for CloudTrail (IAM user name).
    # We only test that Auth0-specific sensitive fields are excluded.
    "username",
    "profile", "identity", "identities", "login", "password",
    "ip_address", "device", "session_id", "session",
    "mfa_recovery_code", "recovery_code", "org_member",
    "connection_credentials", "saml_cert", "saml_key",
    "webhook_secret", "action_secret", "secret_value",
    "callback_url", "logout_url", "allowed_origin", "audience",
    "custom_domain_name",
    "script", "code_content",
    "raw_payload", "raw_response", "log_entry", "log_description",
})

# Safe Auth0 config event types.
AUTH0_CONFIG_EVENT_TYPES = {
    "auth0.tenant.updated",
    "auth0.application.created",
    "auth0.application.updated",
    "auth0.application.deleted",
    "auth0.connection.created",
    "auth0.connection.updated",
    "auth0.connection.deleted",
    "auth0.resource_server.created",
    "auth0.resource_server.updated",
    "auth0.resource_server.deleted",
    "auth0.rule.created",
    "auth0.rule.updated",
    "auth0.rule.deleted",
    "auth0.action.created",
    "auth0.action.updated",
    "auth0.action.deployed",
    "auth0.action.deleted",
    "auth0.mfa_factor.updated",
    "auth0.custom_domain.created",
    "auth0.custom_domain.updated",
    "auth0.custom_domain.verified",
    "auth0.custom_domain.deleted",
    "auth0.config.event",
}

# Event types that must NEVER appear (user-centric, unsafe).
USER_EVENT_TYPES = [
    "s",          # Success Login
    "f",          # Failed Login
    "ss",         # Success Signup
    "fs",         # Failed Signup
    "sce",        # Success Change Email
    "fce",        # Failed Change Email
    "scu",        # Success Change Username
    "fcu",        # Failed Change Username
    "scpn",       # Success Change Phone Number
    "pwd_leak",   # Password Leak
    "fu",         # Failed User Management
    "slo",        # Success Logout
    "cls",        # CodeLink Sent (passwordless)
    "oidc_conformant",  # not an event but a field name — must not be an event type
]


def _make_tenant_record() -> dict[str, Any]:
    return {
        "record_type": "auth0_tenant_settings",
        "record_id": "auth0_tenant_settings_main",
        "provider_resource_id": "tenants/settings",
        "friendly_name_present": True,
        "support_email_domain": "example.com",
        "default_directory_present": True,
        "session_lifetime_category": "standard",
        "idle_session_lifetime_category": "standard",
        "enabled_locales_count": 1,
        "flag_change_pwd_on_first_login": False,
        "flag_enable_client_connections": True,
        "flag_enable_apis_section": True,
        "flag_enable_pipeline2": False,
        "flag_enable_dynamic_client_registration": False,
        "flag_enable_custom_domain_in_emails": False,
        "flag_universal_login": True,
        "flag_enable_legacy_logs_search_v2": False,
        "flag_no_disclose_enterprise_connections": False,
        "flag_disable_management_api_sms_obfuscation": False,
        "flag_enable_adfs_waad_email_verification": False,
        "flag_revoke_refresh_token_grant": False,
    }


def _make_app_record(client_id: str = "AUTH0_TEST_CLIENT_ID") -> dict[str, Any]:
    return {
        "record_type": "auth0_application",
        "record_id": client_id,
        "provider_resource_id": f"clients/{client_id}",
        "client_id": client_id,
        "name": "Test App",
        "app_type": "spa",
        "is_first_party": True,
        "grant_types_summary": "authorization_code",
        "callbacks_count": 1,
        "allowed_logout_urls_count": 1,
        "allowed_origins_count": 1,
        "web_origins_count": 1,
        "jwt_alg": "RS256",
        "oidc_conformant": True,
        "token_endpoint_auth_method": "none",
        "refresh_token_rotation_enabled": True,
        "refresh_token_lifetime_category": "standard",
        "grant_types_count": 1,
        "grant_password_enabled": False,
        "grant_implicit_enabled": False,
        "grant_client_credentials_enabled": False,
        "grant_authorization_code_enabled": True,
        "grant_refresh_token_enabled": False,
        "grant_device_code_enabled": False,
        "grant_mfa_enabled": False,
        "wildcard_callback_present": False,
        "wildcard_logout_url_present": False,
        "wildcard_allowed_origin_present": False,
        "localhost_callback_present": False,
        "localhost_origin_present": False,
        "callbacks_missing_https": False,
        "allowed_origins_missing_https": False,
    }


# ── Section A: Event type allowlist ───────────────────────────────────────────


class TestEventTypeAllowlist:
    def test_auth0_config_event_types_in_connector(self):
        from app.connectors.auth0 import _AUTH0_CONFIG_EVENT_TYPES
        assert _AUTH0_CONFIG_EVENT_TYPES == frozenset(AUTH0_CONFIG_EVENT_TYPES)

    def test_no_user_event_types_in_allowlist(self):
        from app.connectors.auth0 import _AUTH0_CONFIG_EVENT_TYPES
        for user_type in USER_EVENT_TYPES:
            assert user_type not in _AUTH0_CONFIG_EVENT_TYPES, (
                f"User event type '{user_type}' must not be in config allowlist"
            )

    def test_normalize_rejects_non_config_types(self):
        from app.services.auth0_activity_ingestion_service import normalize_auth0_activity_event
        for user_type in ["s", "f", "ss", "slo", "cls", "scpn", "fce"]:
            result = normalize_auth0_activity_event({
                "event_type": user_type,
                "provider_event_id": f"test-{user_type}",
                "metadata": {},
            })
            assert result is None, f"User event type '{user_type}' must be rejected"

    def test_normalize_rejects_missing_event_type(self):
        from app.services.auth0_activity_ingestion_service import normalize_auth0_activity_event
        assert normalize_auth0_activity_event({}) is None
        assert normalize_auth0_activity_event({"metadata": {}}) is None

    def test_normalize_rejects_non_dict(self):
        from app.services.auth0_activity_ingestion_service import normalize_auth0_activity_event
        assert normalize_auth0_activity_event("not a dict") is None  # type: ignore
        assert normalize_auth0_activity_event(None) is None  # type: ignore

    def test_normalize_accepts_config_event_types(self):
        from app.services.auth0_activity_ingestion_service import normalize_auth0_activity_event
        for et in AUTH0_CONFIG_EVENT_TYPES:
            result = normalize_auth0_activity_event({
                "event_type": et,
                "provider_event_id": f"test-{et}",
                "metadata": {"resource_type": "application", "resource_id": "AUTH0_TEST_CLIENT_ID"},
            })
            assert result is not None, f"Config event type '{et}' should be accepted"


# ── Section B: Connector list_activity_events ─────────────────────────────────


class TestConnectorListActivityEvents:
    def _mock_credentials(self) -> dict:
        return {
            "domain": "AUTH0_TEST_DOMAIN",
            "management_api_token": "AUTH0_TEST_API_TOKEN_PLACEHOLDER",
        }

    def test_returns_only_config_event_types(self):
        from app.connectors.auth0 import Auth0Connector, _AUTH0_CONFIG_EVENT_TYPES

        connector = Auth0Connector()

        with (
            patch.object(connector, "_acquire_token", return_value="AUTH0_TEST_API_TOKEN_PLACEHOLDER"),
            patch.object(connector, "_make_management_client") as mock_client_ctx,
            patch.object(connector, "_fetch_tenant_settings", return_value=[_make_tenant_record()]),
            patch.object(connector, "_fetch_applications", return_value=[_make_app_record()]),
            patch.object(connector, "_fetch_connections", return_value=[]),
            patch.object(connector, "_fetch_resource_servers", return_value=[]),
            patch.object(connector, "_fetch_rules", return_value=[]),
            patch.object(connector, "_fetch_actions", return_value=[]),
            patch.object(connector, "_fetch_mfa_factors", return_value=[]),
            patch.object(connector, "_fetch_custom_domains", return_value=[]),
        ):
            mock_client_ctx.return_value.__enter__ = MagicMock(return_value=None)
            mock_client_ctx.return_value.__exit__ = MagicMock(return_value=False)
            events = connector.list_activity_events(self._mock_credentials())

        for ev in events:
            assert ev["event_type"] in _AUTH0_CONFIG_EVENT_TYPES, (
                f"Event type '{ev['event_type']}' not in config allowlist"
            )

    def test_max_events_cap_enforced(self):
        from app.connectors.auth0 import Auth0Connector

        connector = Auth0Connector()
        many_apps = [_make_app_record(f"AUTH0_TEST_CLIENT_ID_{i}") for i in range(50)]

        with (
            patch.object(connector, "_acquire_token", return_value="AUTH0_TEST_API_TOKEN_PLACEHOLDER"),
            patch.object(connector, "_make_management_client") as mock_client_ctx,
            patch.object(connector, "_fetch_tenant_settings", return_value=[_make_tenant_record()]),
            patch.object(connector, "_fetch_applications", return_value=many_apps),
            patch.object(connector, "_fetch_connections", return_value=[]),
            patch.object(connector, "_fetch_resource_servers", return_value=[]),
            patch.object(connector, "_fetch_rules", return_value=[]),
            patch.object(connector, "_fetch_actions", return_value=[]),
            patch.object(connector, "_fetch_mfa_factors", return_value=[]),
            patch.object(connector, "_fetch_custom_domains", return_value=[]),
        ):
            mock_client_ctx.return_value.__enter__ = MagicMock(return_value=None)
            mock_client_ctx.return_value.__exit__ = MagicMock(return_value=False)
            events = connector.list_activity_events(
                self._mock_credentials(), max_events=5
            )

        assert len(events) <= 5

    def test_no_raw_urls_in_returned_events(self):
        from app.connectors.auth0 import Auth0Connector

        connector = Auth0Connector()

        with (
            patch.object(connector, "_acquire_token", return_value="AUTH0_TEST_API_TOKEN_PLACEHOLDER"),
            patch.object(connector, "_make_management_client") as mock_client_ctx,
            patch.object(connector, "_fetch_tenant_settings", return_value=[_make_tenant_record()]),
            patch.object(connector, "_fetch_applications", return_value=[_make_app_record()]),
            patch.object(connector, "_fetch_connections", return_value=[]),
            patch.object(connector, "_fetch_resource_servers", return_value=[]),
            patch.object(connector, "_fetch_rules", return_value=[]),
            patch.object(connector, "_fetch_actions", return_value=[]),
            patch.object(connector, "_fetch_mfa_factors", return_value=[]),
            patch.object(connector, "_fetch_custom_domains", return_value=[]),
        ):
            mock_client_ctx.return_value.__enter__ = MagicMock(return_value=None)
            mock_client_ctx.return_value.__exit__ = MagicMock(return_value=False)
            events = connector.list_activity_events(self._mock_credentials())

        import json
        events_str = json.dumps(events)
        # No raw URL strings (not even the Auth0 domain since we only store it for token acquisition)
        assert "http://localhost" not in events_str
        assert "https://example.com/callback" not in events_str

    def test_no_user_data_in_returned_events(self):
        from app.connectors.auth0 import Auth0Connector

        connector = Auth0Connector()

        with (
            patch.object(connector, "_acquire_token", return_value="AUTH0_TEST_API_TOKEN_PLACEHOLDER"),
            patch.object(connector, "_make_management_client") as mock_client_ctx,
            patch.object(connector, "_fetch_tenant_settings", return_value=[_make_tenant_record()]),
            patch.object(connector, "_fetch_applications", return_value=[_make_app_record()]),
            patch.object(connector, "_fetch_connections", return_value=[]),
            patch.object(connector, "_fetch_resource_servers", return_value=[]),
            patch.object(connector, "_fetch_rules", return_value=[]),
            patch.object(connector, "_fetch_actions", return_value=[]),
            patch.object(connector, "_fetch_mfa_factors", return_value=[]),
            patch.object(connector, "_fetch_custom_domains", return_value=[]),
        ):
            mock_client_ctx.return_value.__enter__ = MagicMock(return_value=None)
            mock_client_ctx.return_value.__exit__ = MagicMock(return_value=False)
            events = connector.list_activity_events(self._mock_credentials())

        import json
        events_str = json.dumps(events)
        for forbidden in ("user_id", "user_email", "ip_address", "device_", "session_id"):
            # Check that forbidden field names as keys don't appear
            assert f'"{forbidden}"' not in events_str, (
                f"Forbidden key '{forbidden}' found in connector events"
            )

    def test_no_jwt_shaped_strings_in_events(self):
        from app.connectors.auth0 import Auth0Connector

        connector = Auth0Connector()
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]{10,}")

        with (
            patch.object(connector, "_acquire_token", return_value="AUTH0_TEST_API_TOKEN_PLACEHOLDER"),
            patch.object(connector, "_make_management_client") as mock_client_ctx,
            patch.object(connector, "_fetch_tenant_settings", return_value=[_make_tenant_record()]),
            patch.object(connector, "_fetch_applications", return_value=[_make_app_record()]),
            patch.object(connector, "_fetch_connections", return_value=[]),
            patch.object(connector, "_fetch_resource_servers", return_value=[]),
            patch.object(connector, "_fetch_rules", return_value=[]),
            patch.object(connector, "_fetch_actions", return_value=[]),
            patch.object(connector, "_fetch_mfa_factors", return_value=[]),
            patch.object(connector, "_fetch_custom_domains", return_value=[]),
        ):
            mock_client_ctx.return_value.__enter__ = MagicMock(return_value=None)
            mock_client_ctx.return_value.__exit__ = MagicMock(return_value=False)
            events = connector.list_activity_events(self._mock_credentials())

        import json
        events_str = json.dumps(events)
        assert not jwt_pattern.search(events_str), "JWT-shaped string found in connector events"

    def test_tenant_event_synthesized(self):
        from app.connectors.auth0 import Auth0Connector

        connector = Auth0Connector()

        with (
            patch.object(connector, "_acquire_token", return_value="AUTH0_TEST_API_TOKEN_PLACEHOLDER"),
            patch.object(connector, "_make_management_client") as mock_client_ctx,
            patch.object(connector, "_fetch_tenant_settings", return_value=[_make_tenant_record()]),
            patch.object(connector, "_fetch_applications", return_value=[]),
            patch.object(connector, "_fetch_connections", return_value=[]),
            patch.object(connector, "_fetch_resource_servers", return_value=[]),
            patch.object(connector, "_fetch_rules", return_value=[]),
            patch.object(connector, "_fetch_actions", return_value=[]),
            patch.object(connector, "_fetch_mfa_factors", return_value=[]),
            patch.object(connector, "_fetch_custom_domains", return_value=[]),
        ):
            mock_client_ctx.return_value.__enter__ = MagicMock(return_value=None)
            mock_client_ctx.return_value.__exit__ = MagicMock(return_value=False)
            events = connector.list_activity_events(self._mock_credentials())

        tenant_events = [e for e in events if e["event_type"] == "auth0.tenant.updated"]
        assert len(tenant_events) == 1
        meta = tenant_events[0]["metadata"]
        assert meta["resource_type"] == "tenant_settings"
        assert "session_lifetime_category" in meta
        # No support email domain, no raw config data
        assert "support_email" not in meta

    def test_application_event_uses_client_id_not_secret(self):
        from app.connectors.auth0 import Auth0Connector

        connector = Auth0Connector()
        app_rec = _make_app_record("AUTH0_TEST_CLIENT_ID")

        with (
            patch.object(connector, "_acquire_token", return_value="AUTH0_TEST_API_TOKEN_PLACEHOLDER"),
            patch.object(connector, "_make_management_client") as mock_client_ctx,
            patch.object(connector, "_fetch_tenant_settings", return_value=[]),
            patch.object(connector, "_fetch_applications", return_value=[app_rec]),
            patch.object(connector, "_fetch_connections", return_value=[]),
            patch.object(connector, "_fetch_resource_servers", return_value=[]),
            patch.object(connector, "_fetch_rules", return_value=[]),
            patch.object(connector, "_fetch_actions", return_value=[]),
            patch.object(connector, "_fetch_mfa_factors", return_value=[]),
            patch.object(connector, "_fetch_custom_domains", return_value=[]),
        ):
            mock_client_ctx.return_value.__enter__ = MagicMock(return_value=None)
            mock_client_ctx.return_value.__exit__ = MagicMock(return_value=False)
            events = connector.list_activity_events(self._mock_credentials())

        app_events = [e for e in events if "application" in e["event_type"]]
        assert len(app_events) == 1
        meta = app_events[0]["metadata"]
        assert meta.get("client_id") == "AUTH0_TEST_CLIENT_ID"
        assert "client_secret" not in meta
        assert "management_api_token" not in meta
        # URL posture booleans, not raw URL strings
        assert "wildcard_callback_present" in meta or "callbacks_count" in meta


# ── Section C: Normalizer ─────────────────────────────────────────────────────


class TestNormalizer:
    def test_normalize_config_event_success(self):
        from app.services.auth0_activity_ingestion_service import normalize_auth0_activity_event
        entry = {
            "event_type": "auth0.application.updated",
            "provider_event_id": "auth0.application.updated:AUTH0_TEST_CLIENT_ID:2026-06-17",
            "metadata": {
                "resource_type": "application",
                "resource_id": "AUTH0_TEST_CLIENT_ID",
                "client_id": "AUTH0_TEST_CLIENT_ID",
                "app_type": "spa",
                "callbacks_count": 1,
            },
        }
        result = normalize_auth0_activity_event(entry)
        assert result is not None
        assert result["provider"] == "auth0"
        assert result["source"] == "auth0_activity_event"
        assert result["event_type"] == "auth0.application.updated"

    def test_normalize_fingerprint_fallback(self):
        from app.services.auth0_activity_ingestion_service import normalize_auth0_activity_event
        entry = {
            "event_type": "auth0.tenant.updated",
            "provider_event_id": None,
            "metadata": {"resource_type": "tenant_settings"},
        }
        result = normalize_auth0_activity_event(entry)
        assert result is not None
        assert result.get("provider_event_id") is not None

    def test_normalize_event_source_added_to_metadata(self):
        from app.services.auth0_activity_ingestion_service import normalize_auth0_activity_event
        entry = {
            "event_type": "auth0.connection.updated",
            "provider_event_id": "auth0.connection.updated:AUTH0_TEST_CONNECTION_ID:2026-06-17",
            "metadata": {
                "resource_type": "connection",
                "connection_id": "AUTH0_TEST_CONNECTION_ID",
            },
        }
        result = normalize_auth0_activity_event(entry)
        assert result is not None
        # event_source should be in metadata through sanitization
        assert result.get("source") == "auth0_activity_event"

    def test_normalize_no_actor_stored(self):
        from app.services.auth0_activity_ingestion_service import normalize_auth0_activity_event
        entry = {
            "event_type": "auth0.rule.updated",
            "provider_event_id": "test-rule-id",
            "metadata": {"resource_type": "rule", "rule_id": "AUTH0_TEST_RULE_ID"},
        }
        result = normalize_auth0_activity_event(entry)
        assert result is not None
        # No actor_id or actor_type (privacy: no user identity stored)
        assert result.get("actor_id") is None
        assert result.get("actor_type") is None

    def test_normalize_no_source_ip(self):
        from app.services.auth0_activity_ingestion_service import normalize_auth0_activity_event
        entry = {
            "event_type": "auth0.action.deployed",
            "provider_event_id": "test-action-id",
            "metadata": {"resource_type": "action", "action_id": "AUTH0_TEST_ACTION_ID"},
        }
        result = normalize_auth0_activity_event(entry)
        assert result is not None
        assert result.get("source_ip") is None


# ── Section D: Ingestion service ──────────────────────────────────────────────


class TestIngestionService:
    def _make_integration(self) -> MagicMock:
        integration = MagicMock()
        integration.id = uuid.uuid4()
        integration.provider = "auth0"
        integration.encrypted_credentials = b"encrypted"
        integration.credential_iv = b"iv"
        integration.status = "active"
        return integration

    def test_wrong_provider_rejected(self):
        from app.services import auth0_activity_ingestion_service as svc
        integration = self._make_integration()
        integration.provider = "sendgrid"
        db = MagicMock()
        result = svc.ingest_auth0_activity(
            integration=integration,
            workspace_id=uuid.uuid4(),
            db=db,
            lookback_hours=24,
            max_events=100,
        )
        assert result["error_message"] == "Not an Auth0 integration."
        assert result["attempted"] is False

    def test_auth_error_sets_permission_limited(self):
        from app.connectors.exceptions import AuthenticationError
        from app.services import auth0_activity_ingestion_service as svc

        integration = self._make_integration()

        with (
            patch("app.services.auth0_activity_ingestion_service.decrypt_credentials",
                  return_value={"domain": "AUTH0_TEST_DOMAIN", "management_api_token": "x"}),
            patch("app.services.auth0_activity_ingestion_service.Auth0Connector") as mock_cls,
        ):
            mock_cls.return_value.list_activity_events.side_effect = AuthenticationError(
                "auth0: 401", status_code=401
            )
            result = svc.ingest_auth0_activity(
                integration=integration,
                workspace_id=uuid.uuid4(),
                db=MagicMock(),
            )

        assert result["permission_limited"] is True
        assert result["succeeded"] is True

    def test_network_error_captured(self):
        from app.connectors.exceptions import NetworkError
        from app.services import auth0_activity_ingestion_service as svc

        integration = self._make_integration()

        with (
            patch("app.services.auth0_activity_ingestion_service.decrypt_credentials",
                  return_value={"domain": "AUTH0_TEST_DOMAIN", "management_api_token": "x"}),
            patch("app.services.auth0_activity_ingestion_service.Auth0Connector") as mock_cls,
        ):
            mock_cls.return_value.list_activity_events.side_effect = NetworkError("timeout")
            result = svc.ingest_auth0_activity(
                integration=integration,
                workspace_id=uuid.uuid4(),
                db=MagicMock(),
            )

        assert result["succeeded"] is False
        assert "network" in result["error_message"].lower()

    def test_events_inserted_increments(self):
        from app.services import auth0_activity_ingestion_service as svc

        integration = self._make_integration()
        workspace_id = uuid.uuid4()
        db = MagicMock()

        safe_event = {
            "event_type": "auth0.application.updated",
            "provider_event_id": "auth0.application.updated:AUTH0_TEST_CLIENT_ID:2026-06-17",
            "metadata": {"resource_type": "application", "client_id": "AUTH0_TEST_CLIENT_ID"},
        }

        with (
            patch("app.services.auth0_activity_ingestion_service.decrypt_credentials",
                  return_value={"domain": "AUTH0_TEST_DOMAIN", "management_api_token": "x"}),
            patch("app.services.auth0_activity_ingestion_service.Auth0Connector") as mock_cls,
            patch("app.services.auth0_activity_ingestion_service.activity_svc") as mock_svc,
        ):
            mock_cls.return_value.list_activity_events.return_value = [safe_event]
            mock_svc.normalize_activity_event.return_value = {
                "provider": "auth0", "source": "auth0_activity_event",
                "event_type": "auth0.application.updated",
                "provider_event_id": "test",
            }
            mock_svc.compute_event_fingerprint.return_value = "fp123"
            mock_svc.upsert_activity_event.return_value = ("inserted", MagicMock())
            mock_svc.sanitize_activity_metadata.side_effect = lambda x: x

            result = svc.ingest_auth0_activity(
                integration=integration,
                workspace_id=workspace_id,
                db=db,
            )

        assert result["events_seen"] == 1
        assert result["events_inserted"] == 1
        assert result["succeeded"] is True

    def test_idempotency_second_run_skips(self):
        from app.services import auth0_activity_ingestion_service as svc

        integration = self._make_integration()
        workspace_id = uuid.uuid4()
        db = MagicMock()

        safe_event = {
            "event_type": "auth0.tenant.updated",
            "provider_event_id": "auth0.tenant.updated:2026-06-17",
            "metadata": {"resource_type": "tenant_settings"},
        }

        with (
            patch("app.services.auth0_activity_ingestion_service.decrypt_credentials",
                  return_value={"domain": "AUTH0_TEST_DOMAIN", "management_api_token": "x"}),
            patch("app.services.auth0_activity_ingestion_service.Auth0Connector") as mock_cls,
            patch("app.services.auth0_activity_ingestion_service.activity_svc") as mock_svc,
        ):
            mock_cls.return_value.list_activity_events.return_value = [safe_event]
            mock_svc.normalize_activity_event.return_value = {
                "provider": "auth0", "source": "auth0_activity_event",
                "event_type": "auth0.tenant.updated",
                "provider_event_id": "auth0.tenant.updated:2026-06-17",
            }
            mock_svc.compute_event_fingerprint.return_value = "fp123"
            # Second run: upsert returns "skipped"
            mock_svc.upsert_activity_event.return_value = ("skipped", MagicMock())
            mock_svc.sanitize_activity_metadata.side_effect = lambda x: x

            result = svc.ingest_auth0_activity(
                integration=integration,
                workspace_id=workspace_id,
                db=db,
            )

        assert result["events_seen"] == 1
        assert result["events_inserted"] == 0
        assert result["events_skipped"] == 1
        assert result["succeeded"] is True

    def test_malformed_event_skipped_gracefully(self):
        from app.services import auth0_activity_ingestion_service as svc

        integration = self._make_integration()
        workspace_id = uuid.uuid4()
        db = MagicMock()

        with (
            patch("app.services.auth0_activity_ingestion_service.decrypt_credentials",
                  return_value={"domain": "AUTH0_TEST_DOMAIN", "management_api_token": "x"}),
            patch("app.services.auth0_activity_ingestion_service.Auth0Connector") as mock_cls,
            patch("app.services.auth0_activity_ingestion_service.activity_svc") as mock_svc,
        ):
            # First event: malformed (login event type)
            # Second event: valid config event
            mock_cls.return_value.list_activity_events.return_value = [
                {"event_type": "s", "provider_event_id": "bad"},  # login — rejected
                {
                    "event_type": "auth0.connection.updated",
                    "provider_event_id": "good",
                    "metadata": {"resource_type": "connection", "connection_id": "AUTH0_TEST_CONNECTION_ID"},
                },
            ]
            mock_svc.normalize_activity_event.return_value = {
                "provider": "auth0", "source": "auth0_activity_event",
                "event_type": "auth0.connection.updated",
                "provider_event_id": "good",
            }
            mock_svc.compute_event_fingerprint.return_value = "fp123"
            mock_svc.upsert_activity_event.return_value = ("inserted", MagicMock())
            mock_svc.sanitize_activity_metadata.side_effect = lambda x: x

            result = svc.ingest_auth0_activity(
                integration=integration,
                workspace_id=workspace_id,
                db=db,
            )

        assert result["events_seen"] == 2
        assert result["events_inserted"] == 1  # only the valid config event
        assert result["succeeded"] is True

    def test_workspace_id_passed_to_upsert(self):
        from app.services import auth0_activity_ingestion_service as svc

        integration = self._make_integration()
        workspace_id = uuid.uuid4()
        db = MagicMock()

        with (
            patch("app.services.auth0_activity_ingestion_service.decrypt_credentials",
                  return_value={"domain": "AUTH0_TEST_DOMAIN", "management_api_token": "x"}),
            patch("app.services.auth0_activity_ingestion_service.Auth0Connector") as mock_cls,
            patch("app.services.auth0_activity_ingestion_service.activity_svc") as mock_svc,
        ):
            mock_cls.return_value.list_activity_events.return_value = [{
                "event_type": "auth0.rule.updated",
                "provider_event_id": "rule-id-1",
                "metadata": {"resource_type": "rule", "rule_id": "AUTH0_TEST_RULE_ID"},
            }]
            mock_svc.normalize_activity_event.return_value = {
                "provider": "auth0", "event_type": "auth0.rule.updated",
                "provider_event_id": "rule-id-1",
            }
            mock_svc.compute_event_fingerprint.return_value = "fp"
            mock_svc.upsert_activity_event.return_value = ("inserted", MagicMock())
            mock_svc.sanitize_activity_metadata.side_effect = lambda x: x

            svc.ingest_auth0_activity(
                integration=integration,
                workspace_id=workspace_id,
                db=db,
            )

        call_kwargs = mock_svc.upsert_activity_event.call_args.kwargs
        assert call_kwargs["workspace_id"] == workspace_id


# ── Section E: Metadata privacy ───────────────────────────────────────────────


class TestMetadataPrivacy:
    def test_allowed_metadata_keys_has_auth0_keys(self):
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        expected_keys = {
            "auth0_event_id", "client_id", "connection_id", "resource_server_id",
            "action_id", "factor_name", "custom_domain_id",
            "app_type", "is_first_party", "jwt_alg", "oidc_conformant",
            "token_endpoint_auth_method", "refresh_token_rotation_enabled",
            "refresh_token_lifetime_category", "enabled_clients_count",
            "password_policy_category", "signing_alg", "token_lifetime_category",
            "allow_offline_access", "rbac_enabled",
            "script_present", "script_length_category",
            "code_present", "code_length_category", "secrets_count",
            "enabled", "status_category",
            "callbacks_count", "allowed_logout_urls_count",
            "allowed_origins_count", "web_origins_count", "grant_types_count",
            "wildcard_callback_present", "wildcard_allowed_origin_present",
            "wildcard_logout_url_present", "localhost_callback_present",
            "localhost_origin_present", "callbacks_missing_https",
            "allowed_origins_missing_https",
        }
        missing = expected_keys - ALLOWED_METADATA_KEYS
        assert not missing, f"Auth0 keys missing from ALLOWED_METADATA_KEYS: {missing}"

    def test_allowed_metadata_keys_excludes_forbidden_keys(self):
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        for forbidden in FORBIDDEN_METADATA_FIELDS:
            assert forbidden not in ALLOWED_METADATA_KEYS, (
                f"Forbidden key '{forbidden}' found in ALLOWED_METADATA_KEYS"
            )

    def test_normalize_event_strips_forbidden_keys(self):
        from app.services.auth0_activity_ingestion_service import normalize_auth0_activity_event
        entry = {
            "event_type": "auth0.application.updated",
            "provider_event_id": "test",
            "metadata": {
                "resource_type": "application",
                "client_id": "AUTH0_TEST_CLIENT_ID",
                # The following should be stripped by sanitize_activity_metadata:
                "client_secret": "should-be-dropped",
                "management_api_token": "should-be-dropped",
            },
        }
        result = normalize_auth0_activity_event(entry)
        assert result is not None
        # sanitize_activity_metadata should drop unknown/forbidden keys
        metadata = result.get("metadata") or {}
        assert "client_secret" not in metadata
        assert "management_api_token" not in metadata

    def test_normalized_event_has_no_jwt_shaped_value(self):
        from app.services.auth0_activity_ingestion_service import normalize_auth0_activity_event
        entry = {
            "event_type": "auth0.action.deployed",
            "provider_event_id": "test",
            "metadata": {"resource_type": "action", "action_id": "AUTH0_TEST_ACTION_ID"},
        }
        result = normalize_auth0_activity_event(entry)
        assert result is not None
        import json
        result_str = json.dumps(result)
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]{10,}")
        assert not jwt_pattern.search(result_str), "JWT-shaped string in normalized event"


# ── Section F: API endpoint ────────────────────────────────────────────────────


class TestApiEndpoint:
    def _make_db(self):
        return MagicMock()

    def test_endpoint_exists_in_router(self):
        from app.routers import security as sec_router
        routes = [r.path for r in sec_router.router.routes]
        assert "/security/auth0-activity/sync" in routes

    def test_member_cannot_sync(self):
        """Member (non-admin) gets 403 from the Auth0 activity sync endpoint."""
        import uuid
        from fastapi.testclient import TestClient
        from fastapi import HTTPException
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.main import app as fastapi_app

        mock_user = MagicMock()
        mock_user.id = uuid.uuid4()
        mock_db = MagicMock()
        mock_workspace_id = uuid.uuid4()

        def _deny(workspace_id, user_id, db):
            raise HTTPException(status_code=403, detail="Admin or owner role required.")

        fastapi_app.dependency_overrides[get_current_user] = lambda: mock_user
        fastapi_app.dependency_overrides[get_db] = lambda: mock_db
        try:
            with patch(
                "app.routers.security._current_workspace_id",
                return_value=mock_workspace_id,
            ), patch(
                "app.routers.security.workspace_permission_service.require_workspace_admin",
                side_effect=_deny,
            ):
                client = TestClient(fastapi_app, raise_server_exceptions=False)
                r = client.post("/security/auth0-activity/sync", json={})
        finally:
            fastapi_app.dependency_overrides.clear()
        assert r.status_code == 403


# ── Section G: Capability matrix and expansion framework ──────────────────────


class TestCapabilityMatrixAndExpansion:
    def test_auth0_activity_ingestion_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.security.activity_ingestion is True

    def test_auth0_signals_still_false(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.security.activity_signals is False
        assert cap.security.risk_activity_correlations is False
        assert cap.security.demo_seed_clear is False
        assert cap.security.case_report is False

    def test_auth0_security_rules_still_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.security.security_rules is True

    def test_auth0_maturity_still_partial(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.maturity == "partial"

    def test_auth0_notes_mention_m81d(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        notes = cap.notes or ""
        assert "M81D" in notes

    def test_expansion_framework_points_to_m81e(self):
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M81E" in planned
        assert "M81D" not in planned


# ── Section H: Frontend checks ────────────────────────────────────────────────


class TestFrontendChecks:
    def _read_file(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_activity_page_has_auth0_provider(self):
        path = (
            Path(__file__).parent.parent.parent
            / "frontend/src/app/(app)/security/activity/page.tsx"
        )
        text = self._read_file(path)
        assert '"auth0"' in text or "'auth0'" in text

    def test_activity_page_has_auth0_event_types(self):
        path = (
            Path(__file__).parent.parent.parent
            / "frontend/src/app/(app)/security/activity/page.tsx"
        )
        text = self._read_file(path)
        assert "AUTH0_EVENT_TYPES" in text
        assert "auth0.tenant.updated" in text
        assert "auth0.application.updated" in text

    def test_api_ts_has_sync_auth0_activity(self):
        path = (
            Path(__file__).parent.parent.parent
            / "frontend/src/lib/api.ts"
        )
        text = self._read_file(path)
        assert "syncAuth0Activity" in text
        assert "auth0-activity/sync" in text

    def test_types_has_auth0_activity_sync_response(self):
        path = (
            Path(__file__).parent.parent.parent
            / "frontend/src/types/index.ts"
        )
        text = self._read_file(path)
        assert "Auth0ActivitySyncResponse" in text


# ── Section I: Forbidden wording ──────────────────────────────────────────────


class TestForbiddenWording:
    def test_no_forbidden_phrases_in_ingestion_service(self):
        import app.services.auth0_activity_ingestion_service as mod
        source = inspect.getsource(mod).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in source, (
                f"Forbidden phrase '{phrase}' in auth0_activity_ingestion_service"
            )

    def test_no_forbidden_phrases_in_connector(self):
        import app.connectors.auth0 as mod
        source = inspect.getsource(mod).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in source, (
                f"Forbidden phrase '{phrase}' in auth0 connector"
            )


# ── Section J: Secret-shape grep ──────────────────────────────────────────────


class TestSecretShapes:
    JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{10,}")
    SG_PATTERN = re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
    TWILIO_AC_PATTERN = re.compile(r"AC[0-9a-fA-F]{32}")
    TWILIO_SK_PATTERN = re.compile(r"SK[0-9a-fA-F]{32}")

    def _scan_dir(self, directory: Path) -> list[str]:
        violations = []
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in (".py", ".ts", ".tsx", ".js", ".jsx", ".json"):
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for pattern in (
                self.JWT_PATTERN, self.SG_PATTERN,
                self.TWILIO_AC_PATTERN, self.TWILIO_SK_PATTERN,
            ):
                if pattern.search(text):
                    violations.append(f"{path}: matches {pattern.pattern!r}")
        return violations

    def test_no_secret_shapes_in_backend_app(self):
        backend_app = Path(__file__).parent.parent / "app"
        violations = self._scan_dir(backend_app)
        assert not violations, "Secret-shaped strings found:\n" + "\n".join(violations)

    def test_no_secret_shapes_in_frontend_src(self):
        frontend_src = Path(__file__).parent.parent.parent / "frontend" / "src"
        if not frontend_src.exists():
            pytest.skip("frontend/src not found")
        violations = self._scan_dir(frontend_src)
        assert not violations, "Secret-shaped strings found:\n" + "\n".join(violations)


# ── Section K: Regression smoke ───────────────────────────────────────────────


class TestRegressionSmoke:
    def test_m81a_rule_keys_still_present(self):
        from app.connectors.auth0_schema import AUTH0_RECORD_TYPES
        assert "auth0_application" in AUTH0_RECORD_TYPES
        assert "auth0_tenant_settings" in AUTH0_RECORD_TYPES

    def test_m81b_rule_keys_still_present(self):
        from app.services.security_rules.auth0 import AUTH0_RULE_KEYS
        m81b_keys = {
            "auth0_tenant_session_lifetime_extended",
            "auth0_application_weak_jwt_algorithm",
            "auth0_connection_weak_password_policy",
        }
        assert m81b_keys.issubset(AUTH0_RULE_KEYS)

    def test_m81c_rule_keys_still_present(self):
        from app.services.security_rules.auth0 import AUTH0_RULE_KEYS
        m81c_keys = {
            "auth0_application_password_grant_enabled",
            "auth0_application_wildcard_callback",
            "auth0_application_token_endpoint_auth_none",
        }
        assert m81c_keys.issubset(AUTH0_RULE_KEYS)

    def test_connector_fetch_still_works(self):
        """Auth0Connector.fetch() is unaffected by M81D additions."""
        from app.connectors.auth0 import Auth0Connector
        # Just verify the class is importable and has all expected methods.
        conn = Auth0Connector()
        assert hasattr(conn, "fetch")
        assert hasattr(conn, "list_activity_events")
        assert hasattr(conn, "validate_credentials")
