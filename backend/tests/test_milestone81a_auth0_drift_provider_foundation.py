"""M81A — Auth0 drift provider foundation tests.

Verifies the Auth0 drift connector, schema, capability matrix integration,
expansion framework update, and sync pipeline wiring that constitute M81A.

Privacy guarantees verified by these tests
------------------------------------------
- client_secret / management_api_token never stored in records or on instance
- Raw callback URLs, logout URLs, allowed origins, web origins stored as counts
- Resource server identifier (audience URI) stored as boolean only
- Custom domain name never stored (domain_present=True only)
- Rule / action script / code content never stored
- Action secrets stored as count only (never names or values)
- User emails, user IDs, profile data, identities never stored
- Connection credentials, passwords, social provider tokens never stored
- MFA enrollment data, recovery codes, phone numbers never stored
- JWKS, private keys, certificate material never stored
- Raw Auth0 API response dicts never stored
- Authorization headers and bearer tokens never in records

Sections
--------
  A. Schema — record type taxonomy
  B. Normalizer unit tests (pure Python, no HTTP required)
  C. Sensitive field scan across all normalizers
  D. Error mapping (mocked HTTP responses)
  E. Connector integration (mocked HTTP)
  F. Provider registration (sync_service, sync_task, capability matrix,
     expansion framework)
  G. Frontend demo-script consistency (skip if frontend absent)
  H. Forbidden wording scan across connector modules
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.connectors.auth0 import Auth0Connector, _email_domain, _token_category, _session_category, _code_length_category, _categorize_factor
from app.connectors.auth0_schema import (
    AUTH0_ACTION,
    AUTH0_APPLICATION,
    AUTH0_CONNECTION,
    AUTH0_CUSTOM_DOMAIN,
    AUTH0_MFA_FACTOR,
    AUTH0_RECORD_TYPES,
    AUTH0_RESOURCE_SERVER,
    AUTH0_RULE,
    AUTH0_TENANT_SETTINGS,
)
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)

# ── Test constants ─────────────────────────────────────────────────────────────

_DOMAIN = "AUTH0_TEST_DOMAIN.auth0.com"
_CLIENT_ID = "AUTH0_TEST_CLIENT_ID"
_CLIENT_SECRET = "AUTH0_TEST_CLIENT_SECRET_PLACEHOLDER"  # safe placeholder
_MGMT_TOKEN = "AUTH0_TEST_API_TOKEN_PLACEHOLDER"

# Credentials using direct token (avoids needing to mock /oauth/token)
_CREDS_TOKEN = {
    "domain": _DOMAIN,
    "management_api_token": _MGMT_TOKEN,
}

# Credentials using client_credentials flow
_CREDS_CC = {
    "domain": _DOMAIN,
    "client_id": _CLIENT_ID,
    "client_secret": _CLIENT_SECRET,
}

# Expected 8 Auth0 record types (M81A baseline).
EXPECTED_RECORD_TYPES = {
    "auth0_tenant_settings",
    "auth0_application",
    "auth0_connection",
    "auth0_resource_server",
    "auth0_rule",
    "auth0_action",
    "auth0_mfa_factor",
    "auth0_custom_domain",
}

# Forbidden field names — must NEVER appear as keys in any normalised record.
_SENSITIVE_FIELD_NAMES: frozenset[str] = frozenset({
    # Auth0 credentials
    "client_secret", "management_api_token", "access_token", "refresh_token",
    "id_token", "token", "bearer", "authorization",
    # JWT / key material
    "signing_secret", "client_assertion", "jwks", "jwt", "private_key",
    "public_key", "certificate", "cert", "signing_key",
    # Raw URL fields (stored as counts only)
    "callbacks", "allowed_logout_urls", "allowed_origins", "web_origins",
    "callback_url", "redirect_uri", "initiate_login_uri",
    # Resource server audience URI (stored as boolean only)
    "identifier", "audience",
    # Custom domain name (stored as boolean only)
    "domain",
    # Script / code content
    "script", "code",
    # Connection credentials
    "password", "client_password", "ldap_password",
    # User data
    "user_id", "email", "phone_number", "profile",
    "identities", "user_metadata", "app_metadata",
    # Verification / DNS
    "verification_token", "cname_api_key", "origin_domain_name",
    # Raw responses
    "raw_response", "raw_payload",
})

# ── Forbidden claim phrases ────────────────────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)


# ════════════════════════════════════════════════════════════════════════════
# Section A — Schema / record type taxonomy
# ════════════════════════════════════════════════════════════════════════════


def test_auth0_record_types_match_expected():
    assert set(AUTH0_RECORD_TYPES) == EXPECTED_RECORD_TYPES


def test_auth0_record_type_count():
    assert len(AUTH0_RECORD_TYPES) == 8


def test_record_type_constants_are_canonical_lowercase():
    pairs = [
        ("AUTH0_TENANT_SETTINGS", AUTH0_TENANT_SETTINGS),
        ("AUTH0_APPLICATION", AUTH0_APPLICATION),
        ("AUTH0_CONNECTION", AUTH0_CONNECTION),
        ("AUTH0_RESOURCE_SERVER", AUTH0_RESOURCE_SERVER),
        ("AUTH0_RULE", AUTH0_RULE),
        ("AUTH0_ACTION", AUTH0_ACTION),
        ("AUTH0_MFA_FACTOR", AUTH0_MFA_FACTOR),
        ("AUTH0_CUSTOM_DOMAIN", AUTH0_CUSTOM_DOMAIN),
    ]
    for name, val in pairs:
        assert val == name.lower(), (
            f"{name} value ({val!r}) must be its lowercased name ({name.lower()!r})"
        )


def test_record_types_are_all_auth0_prefixed():
    for rt in AUTH0_RECORD_TYPES:
        assert rt.startswith("auth0_"), (
            f"Record type {rt!r} must start with 'auth0_'"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section B — Normalizer unit tests (pure Python, no HTTP)
# ════════════════════════════════════════════════════════════════════════════


class TestNormalizeTenantSettings:
    def _raw(self, **overrides) -> dict:
        base: dict[str, Any] = {
            "friendly_name": "Acme Corp",
            "support_email": "admin@acme-corp.example.com",
            "support_url": "https://acme-corp.example.com/support",
            "default_directory": "Username-Password-Authentication",
            "session_lifetime": 72,   # hours
            "idle_session_lifetime": 24,
            "enabled_locales": ["en", "fr", "de"],
            "flags": {
                "change_pwd_on_first_login": True,
                "universal_login": True,
                "enable_pipeline2": False,
                "enable_client_connections": True,
            },
        }
        base.update(overrides)
        return base

    def test_record_type_and_id(self):
        rec = Auth0Connector._normalize_tenant_settings(self._raw())
        assert rec["record_type"] == AUTH0_TENANT_SETTINGS
        assert rec["record_id"] == "auth0_tenant_settings_main"

    def test_friendly_name_present(self):
        rec = Auth0Connector._normalize_tenant_settings(self._raw())
        assert rec["friendly_name_present"] is True

    def test_friendly_name_absent(self):
        rec = Auth0Connector._normalize_tenant_settings(self._raw(friendly_name=""))
        assert rec["friendly_name_present"] is False

    def test_support_email_domain_only(self):
        rec = Auth0Connector._normalize_tenant_settings(self._raw())
        # Only domain part stored — never the full email
        assert rec["support_email_domain"] == "acme-corp.example.com"
        # Full email must not appear anywhere in the record
        assert "admin@acme-corp.example.com" not in str(rec)

    def test_support_url_not_stored(self):
        rec = Auth0Connector._normalize_tenant_settings(self._raw())
        assert "support_url" not in rec
        assert "https://acme-corp.example.com/support" not in str(rec)

    def test_default_directory_present(self):
        rec = Auth0Connector._normalize_tenant_settings(self._raw())
        assert rec["default_directory_present"] is True

    def test_session_lifetime_category(self):
        # 72 hours → "standard"
        rec = Auth0Connector._normalize_tenant_settings(self._raw(session_lifetime=72))
        assert rec["session_lifetime_category"] == "standard"

    def test_idle_session_lifetime_category(self):
        # 24 hours is on the boundary; < 24 is "short", >= 24 is "standard"
        rec = Auth0Connector._normalize_tenant_settings(self._raw(idle_session_lifetime=12))
        assert rec["idle_session_lifetime_category"] == "short"

    def test_enabled_locales_count(self):
        rec = Auth0Connector._normalize_tenant_settings(self._raw())
        assert rec["enabled_locales_count"] == 3

    def test_flag_universal_login(self):
        rec = Auth0Connector._normalize_tenant_settings(self._raw())
        assert rec["flag_universal_login"] is True

    def test_flag_enable_pipeline2_false(self):
        rec = Auth0Connector._normalize_tenant_settings(self._raw())
        assert rec["flag_enable_pipeline2"] is False

    def test_empty_flags_dict(self):
        rec = Auth0Connector._normalize_tenant_settings(self._raw(flags={}))
        assert rec["flag_change_pwd_on_first_login"] is False
        assert rec["flag_universal_login"] is False

    def test_missing_flags(self):
        raw = self._raw()
        del raw["flags"]
        rec = Auth0Connector._normalize_tenant_settings(raw)
        assert rec["flag_universal_login"] is False


class TestNormalizeApplication:
    def _raw(self, **overrides) -> dict:
        base: dict[str, Any] = {
            "client_id": "AUTH0_TEST_CLIENT_ID",
            "client_secret": "SECRET_MUST_NOT_APPEAR",  # present in API response
            "name": "My SPA Application",
            "app_type": "spa",
            "is_first_party": True,
            "grant_types": ["authorization_code", "refresh_token"],
            "callbacks": ["https://app.example.com/callback"],
            "allowed_logout_urls": ["https://app.example.com"],
            "allowed_origins": ["https://app.example.com"],
            "web_origins": ["https://app.example.com"],
            "jwt_configuration": {"alg": "RS256"},
            "oidc_conformant": True,
            "token_endpoint_auth_method": "none",
            "refresh_token": {
                "rotation_type": "rotating",
                "token_lifetime": 2592000,  # 30 days in seconds
            },
        }
        base.update(overrides)
        return base

    def test_record_type(self):
        rec = Auth0Connector._normalize_application(self._raw())
        assert rec["record_type"] == AUTH0_APPLICATION

    def test_client_id_stored(self):
        rec = Auth0Connector._normalize_application(self._raw())
        assert rec["client_id"] == "AUTH0_TEST_CLIENT_ID"

    def test_client_secret_never_stored(self):
        rec = Auth0Connector._normalize_application(self._raw())
        assert "SECRET_MUST_NOT_APPEAR" not in str(rec)
        assert "client_secret" not in rec

    def test_callbacks_as_count_only(self):
        rec = Auth0Connector._normalize_application(self._raw())
        assert rec["callbacks_count"] == 1
        # Raw URL must not appear
        assert "https://app.example.com/callback" not in str(rec)
        assert "callbacks" not in rec

    def test_logout_urls_as_count_only(self):
        rec = Auth0Connector._normalize_application(self._raw())
        assert rec["allowed_logout_urls_count"] == 1
        assert "allowed_logout_urls" not in rec

    def test_origins_as_counts_only(self):
        rec = Auth0Connector._normalize_application(self._raw())
        assert rec["allowed_origins_count"] == 1
        assert rec["web_origins_count"] == 1
        assert "allowed_origins" not in rec
        assert "web_origins" not in rec

    def test_jwt_alg(self):
        rec = Auth0Connector._normalize_application(self._raw())
        assert rec["jwt_alg"] == "RS256"

    def test_grant_types_summary(self):
        rec = Auth0Connector._normalize_application(self._raw())
        assert "authorization_code" in rec["grant_types_summary"]
        assert "refresh_token" in rec["grant_types_summary"]

    def test_refresh_token_rotation(self):
        rec = Auth0Connector._normalize_application(self._raw())
        assert rec["refresh_token_rotation_enabled"] is True

    def test_refresh_token_lifetime_category(self):
        rec = Auth0Connector._normalize_application(self._raw())
        # 2592000 seconds = 30 days > 24h → "extended"
        assert rec["refresh_token_lifetime_category"] == "extended"

    def test_missing_client_id_returns_none(self):
        raw = self._raw()
        del raw["client_id"]
        assert Auth0Connector._normalize_application(raw) is None

    def test_empty_client_id_returns_none(self):
        assert Auth0Connector._normalize_application({"client_id": ""}) is None

    def test_multiple_callbacks_count(self):
        raw = self._raw()
        raw["callbacks"] = [
            "https://a.example.com/cb",
            "https://b.example.com/cb",
            "https://c.example.com/cb",
        ]
        rec = Auth0Connector._normalize_application(raw)
        assert rec["callbacks_count"] == 3
        # None of the raw URLs should be stored
        for url in raw["callbacks"]:
            assert url not in str(rec)


class TestNormalizeConnection:
    def _raw(self, **overrides) -> dict:
        base: dict[str, Any] = {
            "id": "AUTH0_TEST_CONNECTION_ID",
            "name": "Username-Password-Authentication",
            "strategy": "auth0",
            "enabled_clients": ["clientA", "clientB"],
            "is_domain_connection": False,
            "options": {
                "password_policy": "good",
                "mfa": {"active": True},
                "requires_username": True,
                # Sensitive fields that should never appear in record
                "password_complexity_options": {"min_length": 8},
                "passwordPolicy": "good",
            },
        }
        base.update(overrides)
        return base

    def test_record_type(self):
        rec = Auth0Connector._normalize_connection(self._raw())
        assert rec["record_type"] == AUTH0_CONNECTION

    def test_connection_id_stored(self):
        rec = Auth0Connector._normalize_connection(self._raw())
        assert rec["connection_id"] == "AUTH0_TEST_CONNECTION_ID"

    def test_strategy(self):
        rec = Auth0Connector._normalize_connection(self._raw())
        assert rec["strategy"] == "auth0"

    def test_enabled_clients_count(self):
        rec = Auth0Connector._normalize_connection(self._raw())
        assert rec["enabled_clients_count"] == 2
        # Client IDs must not appear
        assert "clientA" not in str(rec)

    def test_password_policy_category(self):
        rec = Auth0Connector._normalize_connection(self._raw())
        assert rec["password_policy_category"] == "good"

    def test_mfa_enabled(self):
        rec = Auth0Connector._normalize_connection(self._raw())
        assert rec["mfa_enabled"] is True

    def test_options_dict_not_stored(self):
        rec = Auth0Connector._normalize_connection(self._raw())
        assert "options" not in rec
        assert "password_complexity_options" not in rec

    def test_social_connection_no_password_policy(self):
        rec = Auth0Connector._normalize_connection(
            self._raw(strategy="google-oauth2", options={})
        )
        assert rec["password_policy_category"] is None
        assert rec["mfa_enabled"] is None

    def test_missing_id_returns_none(self):
        assert Auth0Connector._normalize_connection({"id": ""}) is None


class TestNormalizeResourceServer:
    def _raw(self, **overrides) -> dict:
        base: dict[str, Any] = {
            "id": "AUTH0_TEST_RS_ID",
            "name": "My API",
            "identifier": "https://api.example.com/",  # audience URI — never stored raw
            "signing_alg": "RS256",
            "token_lifetime": 86400,  # 24h in seconds
            "allow_offline_access": False,
            "skip_consent_for_verifiable_first_party_clients": True,
            "enforce_policies": True,
            "scopes": [
                {"value": "read:users", "description": "Read users"},
                {"value": "write:users", "description": "Write users"},
            ],
        }
        base.update(overrides)
        return base

    def test_record_type(self):
        rec = Auth0Connector._normalize_resource_server(self._raw())
        assert rec["record_type"] == AUTH0_RESOURCE_SERVER

    def test_identifier_as_boolean_only(self):
        rec = Auth0Connector._normalize_resource_server(self._raw())
        assert rec["identifier_present"] is True
        # Raw audience URI must never appear
        assert "https://api.example.com/" not in str(rec)
        assert "identifier" not in rec

    def test_signing_alg(self):
        rec = Auth0Connector._normalize_resource_server(self._raw())
        assert rec["signing_alg"] == "RS256"

    def test_token_lifetime_category(self):
        # 86400 seconds = 24h → "standard"
        rec = Auth0Connector._normalize_resource_server(self._raw())
        assert rec["token_lifetime_category"] == "standard"

    def test_scopes_count(self):
        rec = Auth0Connector._normalize_resource_server(self._raw())
        assert rec["scopes_count"] == 2

    def test_scopes_descriptions_not_stored(self):
        rec = Auth0Connector._normalize_resource_server(self._raw())
        assert "scopes" not in rec
        assert "read:users" not in str(rec)

    def test_rbac_enabled(self):
        rec = Auth0Connector._normalize_resource_server(self._raw())
        assert rec["rbac_enabled"] is True

    def test_missing_id_returns_none(self):
        assert Auth0Connector._normalize_resource_server({"id": ""}) is None


class TestNormalizeRule:
    def _raw(self, **overrides) -> dict:
        base: dict[str, Any] = {
            "id": "AUTH0_TEST_RULE_ID",
            "name": "Add roles to token",
            "enabled": True,
            "order": 1,
            "script": "function(user, context, callback) { callback(null, user, context); }",
            "stage": "login_success",
        }
        base.update(overrides)
        return base

    def test_record_type(self):
        rec = Auth0Connector._normalize_rule(self._raw())
        assert rec["record_type"] == AUTH0_RULE

    def test_script_present_true(self):
        rec = Auth0Connector._normalize_rule(self._raw())
        assert rec["script_present"] is True

    def test_script_content_never_stored(self):
        rec = Auth0Connector._normalize_rule(self._raw())
        assert "callback" not in str(rec)
        assert "function(user" not in str(rec)
        assert "script" not in rec

    def test_script_length_category(self):
        rec = Auth0Connector._normalize_rule(self._raw())
        assert rec["script_length_category"] == "short"  # < 500 chars

    def test_enabled_flag(self):
        rec = Auth0Connector._normalize_rule(self._raw(enabled=False))
        assert rec["enabled"] is False

    def test_order_stored(self):
        rec = Auth0Connector._normalize_rule(self._raw())
        assert rec["order"] == 1

    def test_stage_stored(self):
        rec = Auth0Connector._normalize_rule(self._raw())
        assert rec["stage"] == "login_success"

    def test_missing_id_returns_none(self):
        assert Auth0Connector._normalize_rule({"id": ""}) is None

    def test_no_script_is_absent_category(self):
        rec = Auth0Connector._normalize_rule(self._raw(script=""))
        assert rec["script_present"] is False
        assert rec["script_length_category"] == "absent"


class TestNormalizeAction:
    def _raw(self, **overrides) -> dict:
        base: dict[str, Any] = {
            "id": "AUTH0_TEST_ACTION_ID",
            "name": "Add user roles",
            "status": "built",
            "runtime": "node18-actions",
            "supported_triggers": [{"id": "post-login", "version": "v3"}],
            "code": "exports.onExecutePostLogin = async (event, api) => {};",
            "deployed_version": {"id": "ver_001", "code": "...", "status": "built"},
            "dependencies": [
                {"name": "axios", "version": "1.0.0"},
                {"name": "lodash", "version": "4.17.21"},
            ],
            "secrets": [
                {"name": "API_KEY"},
                {"name": "SLACK_WEBHOOK"},
            ],
        }
        base.update(overrides)
        return base

    def test_record_type(self):
        rec = Auth0Connector._normalize_action(self._raw())
        assert rec["record_type"] == AUTH0_ACTION

    def test_code_present_true(self):
        rec = Auth0Connector._normalize_action(self._raw())
        assert rec["code_present"] is True

    def test_code_content_never_stored(self):
        rec = Auth0Connector._normalize_action(self._raw())
        assert "onExecutePostLogin" not in str(rec)
        assert "exports." not in str(rec)
        assert "code" not in rec

    def test_secrets_count_not_values(self):
        rec = Auth0Connector._normalize_action(self._raw())
        assert rec["secrets_count"] == 2
        # Secret names must not appear
        assert "API_KEY" not in str(rec)
        assert "SLACK_WEBHOOK" not in str(rec)

    def test_dependencies_count_not_names(self):
        rec = Auth0Connector._normalize_action(self._raw())
        assert rec["dependencies_count"] == 2
        # Package names must not appear
        assert "axios" not in str(rec)
        assert "lodash" not in str(rec)

    def test_trigger_id(self):
        rec = Auth0Connector._normalize_action(self._raw())
        assert rec["trigger_id"] == "post-login"

    def test_deployed_version_present(self):
        rec = Auth0Connector._normalize_action(self._raw())
        assert rec["deployed_version_present"] is True

    def test_deployed_version_content_not_stored(self):
        rec = Auth0Connector._normalize_action(self._raw())
        assert "ver_001" not in str(rec)

    def test_missing_id_returns_none(self):
        assert Auth0Connector._normalize_action({"id": ""}) is None


class TestNormalizeMfaFactor:
    def _raw(self, **overrides) -> dict:
        base: dict[str, Any] = {
            "name": "sms",
            "enabled": True,
            "trial_expired": False,
        }
        base.update(overrides)
        return base

    def test_record_type(self):
        rec = Auth0Connector._normalize_mfa_factor(self._raw())
        assert rec["record_type"] == AUTH0_MFA_FACTOR

    def test_factor_name(self):
        rec = Auth0Connector._normalize_mfa_factor(self._raw())
        assert rec["factor_name"] == "sms"

    def test_enabled_flag(self):
        rec = Auth0Connector._normalize_mfa_factor(self._raw())
        assert rec["enabled"] is True

    def test_provider_category(self):
        rec = Auth0Connector._normalize_mfa_factor(self._raw())
        assert rec["provider_category"] == "sms"

    def test_webauthn_roaming_category(self):
        rec = Auth0Connector._normalize_mfa_factor(self._raw(name="webauthn-roaming"))
        assert rec["provider_category"] == "webauthn"

    def test_push_notification_category(self):
        rec = Auth0Connector._normalize_mfa_factor(self._raw(name="push-notification"))
        assert rec["provider_category"] == "push"

    def test_missing_name_returns_none(self):
        assert Auth0Connector._normalize_mfa_factor({"name": ""}) is None

    def test_enrollment_data_not_in_record(self):
        raw = self._raw()
        raw["enrollments"] = [{"type": "sms", "phone_number": "+15555551234"}]
        rec = Auth0Connector._normalize_mfa_factor(raw)
        assert "enrollments" not in rec
        assert "+15555551234" not in str(rec)
        assert "phone_number" not in rec


class TestNormalizeCustomDomain:
    def _raw(self, **overrides) -> dict:
        base: dict[str, Any] = {
            "custom_domain_id": "cd_AUTH0_TEST_DOMAIN_ID",
            "domain": "login.acme-corp.example.com",  # customer-identifying, must not be stored
            "primary": True,
            "status": "ready",
            "type": "auth0_managed_certs",
            "tls_policy": "recommended",
            "verification": {
                "methods": [
                    {
                        "name": "txt",
                        "record": "auth0-domain-verify=VERIFICATION_TOKEN_MUST_NOT_APPEAR",
                    }
                ]
            },
        }
        base.update(overrides)
        return base

    def test_record_type(self):
        rec = Auth0Connector._normalize_custom_domain(self._raw())
        assert rec["record_type"] == AUTH0_CUSTOM_DOMAIN

    def test_domain_name_never_stored(self):
        rec = Auth0Connector._normalize_custom_domain(self._raw())
        assert "login.acme-corp.example.com" not in str(rec)
        assert "domain" not in rec
        # domain_present is always True
        assert rec["domain_present"] is True

    def test_status_stored(self):
        rec = Auth0Connector._normalize_custom_domain(self._raw())
        assert rec["status"] == "ready"

    def test_type_stored(self):
        rec = Auth0Connector._normalize_custom_domain(self._raw())
        assert rec["type"] == "auth0_managed_certs"

    def test_primary_stored(self):
        rec = Auth0Connector._normalize_custom_domain(self._raw())
        assert rec["primary"] is True

    def test_tls_policy_stored(self):
        rec = Auth0Connector._normalize_custom_domain(self._raw())
        assert rec["tls_policy_category"] == "recommended"

    def test_verification_token_never_stored(self):
        rec = Auth0Connector._normalize_custom_domain(self._raw())
        assert "VERIFICATION_TOKEN_MUST_NOT_APPEAR" not in str(rec)
        assert "auth0-domain-verify=" not in str(rec)
        assert "record" not in rec

    def test_verification_method_category_safe(self):
        rec = Auth0Connector._normalize_custom_domain(self._raw())
        # Only "txt" label stored, not the token value
        assert rec["verification_method_category"] == "txt"

    def test_missing_id_returns_none(self):
        assert Auth0Connector._normalize_custom_domain({"custom_domain_id": ""}) is None


# ════════════════════════════════════════════════════════════════════════════
# Section C — Sensitive field scan across all normalizers
# ════════════════════════════════════════════════════════════════════════════


def _all_test_records() -> list[dict]:
    """Produce one example record from every normalizer."""
    return [
        Auth0Connector._normalize_tenant_settings({
            "friendly_name": "Test",
            "support_email": "support@test.auth0.example.com",
            "default_directory": "Username-Password",
            "session_lifetime": 168,
            "idle_session_lifetime": 72,
            "enabled_locales": ["en"],
            "flags": {"universal_login": True},
        }),
        Auth0Connector._normalize_application({
            "client_id": "AUTH0_TEST_CLIENT_ID",
            "client_secret": "SECRET_VALUE",
            "name": "Test App",
            "app_type": "spa",
            "grant_types": ["authorization_code"],
            "callbacks": ["https://test.example.com/callback"],
            "allowed_logout_urls": ["https://test.example.com"],
            "allowed_origins": ["https://test.example.com"],
            "web_origins": ["https://test.example.com"],
            "jwt_configuration": {"alg": "RS256"},
            "oidc_conformant": True,
            "token_endpoint_auth_method": "none",
        }),
        Auth0Connector._normalize_connection({
            "id": "AUTH0_TEST_CONNECTION_ID",
            "name": "Username-Password-Authentication",
            "strategy": "auth0",
            "enabled_clients": ["c1", "c2"],
            "is_domain_connection": False,
            "options": {"password_policy": "fair", "mfa": {"active": False}},
        }),
        Auth0Connector._normalize_resource_server({
            "id": "AUTH0_TEST_RS_ID",
            "name": "Test API",
            "identifier": "https://api.test.auth0.example.com/",
            "signing_alg": "RS256",
            "token_lifetime": 3600,
            "allow_offline_access": False,
            "skip_consent_for_verifiable_first_party_clients": False,
            "enforce_policies": False,
            "scopes": [{"value": "read:data", "description": "Read data"}],
        }),
        Auth0Connector._normalize_rule({
            "id": "AUTH0_TEST_RULE_ID",
            "name": "Test Rule",
            "enabled": True,
            "order": 1,
            "script": "function(user, context, callback) { callback(null, user, context); }",
            "stage": "login_success",
        }),
        Auth0Connector._normalize_action({
            "id": "AUTH0_TEST_ACTION_ID",
            "name": "Test Action",
            "status": "built",
            "runtime": "node18-actions",
            "supported_triggers": [{"id": "post-login", "version": "v3"}],
            "code": "exports.onExecutePostLogin = async (event, api) => {};",
            "secrets": [{"name": "MY_SECRET"}],
            "dependencies": [{"name": "axios", "version": "1.0.0"}],
        }),
        Auth0Connector._normalize_mfa_factor({
            "name": "otp",
            "enabled": True,
        }),
        Auth0Connector._normalize_custom_domain({
            "custom_domain_id": "AUTH0_TEST_DOMAIN_ID_CD001",
            "domain": "login.test.auth0.example.com",
            "primary": True,
            "status": "ready",
            "type": "auth0_managed_certs",
            "tls_policy": "recommended",
            "verification": {"methods": [{"name": "txt", "record": "TOKEN_DO_NOT_STORE"}]},
        }),
    ]


def test_no_sensitive_field_name_in_any_record():
    """No normalizer may emit a key whose name is in the sensitive fields list."""
    records = [r for r in _all_test_records() if r is not None]
    assert len(records) == 8, "Expected 8 test records (one per normalizer)"
    for rec in records:
        for key in rec:
            assert key not in _SENSITIVE_FIELD_NAMES, (
                f"Sensitive field name {key!r} found in {rec['record_type']!r} record"
            )


def test_no_raw_url_in_any_record():
    """No normalizer may store raw URL strings from the Auth0 API."""
    forbidden_urls = [
        "https://test.example.com/callback",
        "https://test.example.com",
        "https://api.test.auth0.example.com/",
    ]
    records = [r for r in _all_test_records() if r is not None]
    import json
    blob = json.dumps(records, default=str)
    for url in forbidden_urls:
        assert url not in blob, (
            f"Raw URL {url!r} found in normalized records"
        )


def test_no_raw_secret_or_credential_in_any_record():
    """No normalizer may store credential-like values."""
    sensitive_values = [
        "SECRET_VALUE",        # client_secret from application raw
        "TOKEN_DO_NOT_STORE",  # verification token from custom domain
    ]
    import json
    records = [r for r in _all_test_records() if r is not None]
    blob = json.dumps(records, default=str)
    for val in sensitive_values:
        assert val not in blob, (
            f"Sensitive value {val!r} found in normalized records"
        )


def test_no_domain_name_in_custom_domain_record():
    """Custom domain name (customer-identifying) must never appear in the record."""
    rec = Auth0Connector._normalize_custom_domain({
        "custom_domain_id": "AUTH0_TEST_DOMAIN_ID_CD001",
        "domain": "login.very-specific-company.com",
        "primary": True,
        "status": "ready",
        "type": "auth0_managed_certs",
        "tls_policy": "recommended",
        "verification": {"methods": [{"name": "txt", "record": "TOKEN"}]},
    })
    assert "login.very-specific-company.com" not in str(rec)


def test_no_email_address_in_tenant_record():
    """Full email address must never appear in the tenant settings record."""
    rec = Auth0Connector._normalize_tenant_settings({
        "friendly_name": "Corp",
        "support_email": "support-admin@very-specific-corp.com",
        "flags": {},
    })
    assert "support-admin@very-specific-corp.com" not in str(rec)
    # Domain part IS allowed
    assert rec["support_email_domain"] == "very-specific-corp.com"


# ════════════════════════════════════════════════════════════════════════════
# Section D — Helper functions
# ════════════════════════════════════════════════════════════════════════════


def test_email_domain_extracts_correctly():
    assert _email_domain("admin@example.com") == "example.com"
    assert _email_domain("no-at-sign") == ""
    assert _email_domain(None) == ""
    assert _email_domain(42) == ""
    assert _email_domain("multi@at@example.com") == "example.com"  # rfind finds last @


def test_session_category_thresholds():
    assert _session_category(0) == "very_short"   # 0 hours < 1h
    assert _session_category(1) == "short"        # 1 hour is not < 1 → goes to "short"
    assert _session_category(23) == "short"       # < 24h
    assert _session_category(24) == "standard"    # 24h
    assert _session_category(167) == "standard"   # < 168h
    assert _session_category(168) == "extended"   # >= 168h
    assert _session_category(None) == "very_short"  # 0 hours (default)


def test_token_category_thresholds():
    assert _token_category(0) == "very_short"    # 0s < 15m
    assert _token_category(899) == "very_short"  # < 900s
    assert _token_category(900) == "short"       # 900s = 15m
    assert _token_category(3599) == "short"      # < 1h
    assert _token_category(3600) == "standard"   # 1h
    assert _token_category(86399) == "standard"  # < 24h
    assert _token_category(86400) == "standard"  # 24h — Auth0 default, inclusive of standard
    assert _token_category(86401) == "extended"  # > 24h
    assert _token_category(None) == "very_short"  # default 0


def test_code_length_category():
    assert _code_length_category("") == "absent"
    assert _code_length_category(None) == "absent"
    assert _code_length_category("x" * 499) == "short"
    assert _code_length_category("x" * 500) == "medium"
    assert _code_length_category("x" * 1999) == "medium"
    assert _code_length_category("x" * 2000) == "long"


def test_categorize_factor():
    assert _categorize_factor("sms") == "sms"
    assert _categorize_factor("push-notification") == "push"
    assert _categorize_factor("email") == "email"
    assert _categorize_factor("otp") == "totp"
    assert _categorize_factor("webauthn-roaming") == "webauthn"
    assert _categorize_factor("webauthn-platform") == "webauthn"
    assert _categorize_factor("recovery-code") == "recovery"
    assert _categorize_factor("duo") == "third_party"
    assert _categorize_factor("unknown-factor") == "other"


# ════════════════════════════════════════════════════════════════════════════
# Section E — Connector integration (mocked HTTP)
# ════════════════════════════════════════════════════════════════════════════


def _mock_mgmt_response(data: Any, status_code: int = 200):
    """Build a MagicMock httpx.Response for the Management API."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {}
    resp.json.return_value = data
    return resp


class TestAcquireToken:
    def test_returns_direct_token_without_http(self):
        """When management_api_token is provided, no HTTP call is made."""
        creds = {
            "domain": "test.auth0.com",
            "management_api_token": _MGMT_TOKEN,
        }
        with patch("httpx.post") as mock_post:
            token = Auth0Connector._acquire_token("test.auth0.com", creds)
        assert token == _MGMT_TOKEN
        mock_post.assert_not_called()

    def test_client_credentials_flow_success(self):
        """Client credentials flow returns the access_token from the response."""
        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {
            "access_token": "MINTED_TOKEN_PLACEHOLDER",
            "token_type": "Bearer",
            "expires_in": 86400,
        }
        with patch("httpx.post", return_value=token_resp):
            token = Auth0Connector._acquire_token("test.auth0.com", _CREDS_CC)
        assert token == "MINTED_TOKEN_PLACEHOLDER"

    def test_client_credentials_401_raises_auth_error(self):
        token_resp = MagicMock()
        token_resp.status_code = 401
        with patch("httpx.post", return_value=token_resp):
            with pytest.raises(AuthenticationError):
                Auth0Connector._acquire_token("test.auth0.com", _CREDS_CC)

    def test_client_credentials_403_raises_auth_error(self):
        token_resp = MagicMock()
        token_resp.status_code = 403
        with patch("httpx.post", return_value=token_resp):
            with pytest.raises(AuthenticationError):
                Auth0Connector._acquire_token("test.auth0.com", _CREDS_CC)

    def test_client_credentials_429_raises_rate_limit(self):
        token_resp = MagicMock()
        token_resp.status_code = 429
        token_resp.headers = {}
        with patch("httpx.post", return_value=token_resp):
            with pytest.raises(RateLimitError):
                Auth0Connector._acquire_token("test.auth0.com", _CREDS_CC)

    def test_missing_credentials_raises_auth_error(self):
        with pytest.raises(AuthenticationError):
            Auth0Connector._acquire_token("test.auth0.com", {"domain": "test.auth0.com"})

    def test_no_access_token_in_response_raises_auth_error(self):
        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {"token_type": "Bearer"}
        with patch("httpx.post", return_value=token_resp):
            with pytest.raises(AuthenticationError):
                Auth0Connector._acquire_token("test.auth0.com", _CREDS_CC)


class TestRaiseForStatus:
    def _resp(self, status_code: int, headers: dict | None = None) -> MagicMock:
        r = MagicMock()
        r.status_code = status_code
        r.headers = headers or {}
        return r

    def test_200_no_raise(self):
        Auth0Connector._raise_for_status(self._resp(200))

    def test_401_raises_auth_error(self):
        with pytest.raises(AuthenticationError):
            Auth0Connector._raise_for_status(self._resp(401))

    def test_403_raises_connector_error(self):
        with pytest.raises(ConnectorError):
            Auth0Connector._raise_for_status(self._resp(403))

    def test_404_raises_connector_error(self):
        with pytest.raises(ConnectorError):
            Auth0Connector._raise_for_status(self._resp(404))

    def test_429_raises_rate_limit_error(self):
        with pytest.raises(RateLimitError):
            Auth0Connector._raise_for_status(self._resp(429))

    def test_500_raises_connector_error(self):
        with pytest.raises(ConnectorError):
            Auth0Connector._raise_for_status(self._resp(500))

    def test_422_raises_connector_error(self):
        with pytest.raises(ConnectorError):
            Auth0Connector._raise_for_status(self._resp(422))


class TestFetchSurfaces:
    """Test per-surface fetch methods with mocked Management API client."""

    def _mock_client(self, response_data: Any, status_code: int = 200) -> MagicMock:
        client = MagicMock()
        resp = _mock_mgmt_response(response_data, status_code)
        client.get.return_value = resp
        return client

    def test_fetch_tenant_settings_returns_single_record(self):
        raw_settings = {
            "friendly_name": "Acme",
            "support_email": "ops@acme.example.com",
            "default_directory": "Username-Password",
            "session_lifetime": 168,
            "idle_session_lifetime": 72,
            "enabled_locales": ["en"],
            "flags": {"universal_login": True},
        }
        client = self._mock_client(raw_settings)
        records = Auth0Connector._fetch_tenant_settings(client)
        assert len(records) == 1
        assert records[0]["record_type"] == AUTH0_TENANT_SETTINGS

    def test_fetch_tenant_settings_403_returns_empty(self):
        resp = _mock_mgmt_response({}, 403)
        client = MagicMock()
        client.get.return_value = resp
        records = Auth0Connector._fetch_tenant_settings(client)
        assert records == []

    def test_fetch_applications_normalizes_records(self):
        raw = [
            {
                "client_id": "AUTH0_TEST_CLIENT_ID",
                "client_secret": "DO_NOT_STORE",
                "name": "Test App",
                "app_type": "spa",
                "grant_types": ["authorization_code"],
                "callbacks": ["https://test.example.com/cb"],
                "allowed_logout_urls": [],
                "allowed_origins": [],
                "web_origins": [],
                "jwt_configuration": {"alg": "RS256"},
                "oidc_conformant": True,
                "token_endpoint_auth_method": "none",
            }
        ]
        client = self._mock_client(raw)
        records = Auth0Connector._fetch_applications(client)
        assert len(records) == 1
        assert records[0]["record_type"] == AUTH0_APPLICATION
        assert "DO_NOT_STORE" not in str(records)
        assert "client_secret" not in records[0]

    def test_fetch_connections_normalizes_records(self):
        raw = [
            {
                "id": "AUTH0_TEST_CONNECTION_ID",
                "name": "Username-Password",
                "strategy": "auth0",
                "enabled_clients": ["c1"],
                "is_domain_connection": False,
                "options": {"password_policy": "good"},
            }
        ]
        client = self._mock_client(raw)
        records = Auth0Connector._fetch_connections(client)
        assert len(records) == 1
        assert records[0]["record_type"] == AUTH0_CONNECTION

    def test_fetch_mfa_factors_normalizes_records(self):
        raw = [
            {"name": "sms", "enabled": True},
            {"name": "push-notification", "enabled": False},
            {"name": "otp", "enabled": True},
        ]
        client = self._mock_client(raw)
        records = Auth0Connector._fetch_mfa_factors(client)
        assert len(records) == 3
        assert all(r["record_type"] == AUTH0_MFA_FACTOR for r in records)
        assert {r["factor_name"] for r in records} == {"sms", "push-notification", "otp"}

    def test_fetch_custom_domains_hides_domain_names(self):
        raw = [
            {
                "custom_domain_id": "cd_AUTH0_TEST_DOMAIN_ID",
                "domain": "login.must-not-appear.com",
                "primary": True,
                "status": "ready",
                "type": "auth0_managed_certs",
                "tls_policy": "recommended",
                "verification": {"methods": [{"name": "txt", "record": "TOKEN_HIDDEN"}]},
            }
        ]
        client = self._mock_client(raw)
        records = Auth0Connector._fetch_custom_domains(client)
        assert len(records) == 1
        assert "login.must-not-appear.com" not in str(records)
        assert "TOKEN_HIDDEN" not in str(records)
        assert records[0]["domain_present"] is True

    def test_fetch_rules_hides_script_content(self):
        raw = [
            {
                "id": "AUTH0_TEST_RULE_ID",
                "name": "Test Rule",
                "enabled": True,
                "order": 1,
                "script": "function(user,context,callback){/* DO_NOT_STORE_SCRIPT */}",
                "stage": "login_success",
            }
        ]
        client = self._mock_client(raw)
        records = Auth0Connector._fetch_rules(client)
        assert len(records) == 1
        assert "DO_NOT_STORE_SCRIPT" not in str(records)
        assert records[0]["script_present"] is True

    def test_fetch_actions_hides_code_and_secrets(self):
        raw_actions = {
            "actions": [
                {
                    "id": "AUTH0_TEST_ACTION_ID",
                    "name": "Test Action",
                    "status": "built",
                    "runtime": "node18-actions",
                    "supported_triggers": [{"id": "post-login", "version": "v3"}],
                    "code": "/* DO_NOT_STORE_CODE */",
                    "secrets": [{"name": "SECRET_NAME_HIDDEN"}],
                    "dependencies": [],
                }
            ]
        }
        client = self._mock_client(raw_actions)
        records = Auth0Connector._fetch_actions(client)
        assert len(records) == 1
        assert "DO_NOT_STORE_CODE" not in str(records)
        assert "SECRET_NAME_HIDDEN" not in str(records)
        assert records[0]["secrets_count"] == 1


# ════════════════════════════════════════════════════════════════════════════
# Section F — Provider registration
# ════════════════════════════════════════════════════════════════════════════


def test_auth0_in_supported_providers():
    """Auth0 must be in the sync scheduler's provider set."""
    from app.services.sync_service import create_scheduled_syncs_for_active_integrations
    src = inspect.getsource(create_scheduled_syncs_for_active_integrations)
    assert "auth0" in src, (
        "sync_service._SUPPORTED_PROVIDERS does not include 'auth0'"
    )


def test_auth0_in_sync_task_dispatch():
    """Sync task worker must have an Auth0 connector dispatch branch."""
    from app.workers import sync_task
    src = inspect.getsource(sync_task)
    assert "Auth0Connector" in src, "sync_task missing Auth0Connector dispatch"
    assert '"auth0"' in src or "'auth0'" in src, (
        "sync_task missing auth0 provider check"
    )


def test_auth0_not_logged_credentials_in_sync_task():
    """The sync task dispatch block must include the NEVER-logged security comment."""
    from app.workers import sync_task
    src = inspect.getsource(sync_task)
    # Find the auth0 block
    idx = src.find("auth0")
    assert idx != -1
    block = src[idx: idx + 400]
    assert "NEVER" in block.upper() or "secret" in block.lower(), (
        "auth0 dispatch block should document that credentials are never logged"
    )


def test_capability_matrix_includes_auth0():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("auth0")
    assert cap is not None
    assert cap.provider == "auth0"
    assert cap.label == "Auth0"
    assert cap.category == "auth"


def test_capability_matrix_auth0_drift_only():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("auth0")
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    # drift_risk_classification flipped on in M81B with the core security rules.
    assert cap.drift.drift_risk_classification is True
    # security_rules flipped on in M81B; activity/signals/correlations/demo
    # remain deferred to later M81 milestones.
    assert cap.security.security_rules is True
    # activity_ingestion M81D, activity_signals M81E, correlations M81F,
    # demo M81G — all now complete.
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.maturity == "partial"


def test_capability_matrix_auth0_notes_mention_m81a():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("auth0")
    notes = cap.notes or ""
    assert "M81A" in notes, "Auth0 capability notes must mention M81A"


def test_capability_matrix_auth0_notes_mention_privacy():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("auth0")
    notes = (cap.notes or "").lower()
    # Notes must say what is NOT stored
    assert "never" in notes or "not stored" in notes or "never stored" in notes, (
        "Auth0 notes must document what is not stored"
    )


def test_capability_matrix_auth0_in_partial_list():
    from app.services.provider_capability_matrix_service import (
        PROVIDER_CAPABILITIES, PROVIDER_CAPABILITIES_PARTIAL,
    )
    canonical = {p.provider for p in PROVIDER_CAPABILITIES}
    partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
    assert "auth0" not in canonical, "Auth0 must not be in the canonical 8"
    assert "auth0" in partial, "Auth0 must be in PROVIDER_CAPABILITIES_PARTIAL"


def test_expansion_framework_planned_next_stage_is_m81b():
    """After M81A, planned_next_stage must advance past M81A (M81B or later)."""
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M81A" not in stage, (
        f"M81A is done; pointer must advance past it (got: {stage!r})"
    )
    assert any(tag in stage for tag in ("M81B", "M81C", "M81D", "M81E", "M81F", "M81G", "M81H", "M81I", "M82", "M83", "M84", "M85", "M86", "M87", "M88", "M89", "Kubernetes", "M90", "Sentry")), (
        f"planned_next_stage should point to M81B or beyond after M81A; got: {stage!r}"
    )


def test_expansion_framework_auth0_not_in_recommended_queue():
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    providers = [r["provider"] for r in fw["recommended_next_providers"]]
    assert "auth0" not in providers, (
        "Auth0 launched in M81A and should not be in the recommended queue"
    )


def test_expansion_framework_top_recommendation_is_kubernetes():
    """Regression note: Kubernetes launched its provider architecture
    foundation (Kubernetes message 1 / M89A) and was removed from the
    recommended queue — Sentry (M90A) is now the head."""
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    recs = fw["recommended_next_providers"]
    assert len(recs) > 0
    assert recs[0]["provider"] == "sentry", (
        f"expansion-framework queue head should be sentry; got "
        f"{recs[0]['provider']!r}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section G — Frontend demo-script consistency (skip if tree absent)
# ════════════════════════════════════════════════════════════════════════════

_FE_ROOT_CANDIDATES = (
    Path(__file__).resolve().parents[2] / "frontend" / "src",
)


def _fe_src() -> Path | None:
    for c in _FE_ROOT_CANDIDATES:
        if c.is_dir():
            return c
    return None


def _read_fe(rel: str) -> str:
    root = _fe_src()
    if root is None:
        pytest.skip("frontend/src not mounted")
    return (root / rel).read_text(encoding="utf-8")


def test_fe_demo_script_page_auth0_in_capability_table():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    assert 'provider: "auth0"' in text, (
        "Auth0 must appear in PROVIDER_CAPABILITY_TABLE after M81A"
    )
    assert "Auth0" in text


def test_fe_demo_script_page_auth0_row_demo_true():
    """Auth0 capability row should have demo=true (M81G completed)."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(
        r'provider:\s*"auth0"[^}]*demo:\s*(true|false)',
        text,
        flags=re.DOTALL,
    )
    assert m is not None, "Auth0 row not found in PROVIDER_CAPABILITY_TABLE"
    assert m.group(1) == "true", "Auth0 demo should be true (M81G completed)"


def test_fe_demo_script_page_auth0_not_in_next_providers():
    """Auth0 launched in M81A — must not still be in NEXT_PROVIDERS_BRIEF."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(
        r"const NEXT_PROVIDERS_BRIEF.*?= \[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None, "NEXT_PROVIDERS_BRIEF not found"
    block = m.group(1)
    assert "Auth0" not in block, (
        "Auth0 launched in M81A and must not be in NEXT_PROVIDERS_BRIEF"
    )
    assert '"M81A"' not in block, (
        "Stale M81A milestone reference in NEXT_PROVIDERS_BRIEF"
    )


def test_fe_demo_script_page_stale_m81a_labels_updated():
    """NEXT_PROVIDERS_BRIEF must not have stale M81A/B/C milestone labels for non-Auth0 providers."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(
        r"const NEXT_PROVIDERS_BRIEF.*?= \[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None
    block = m.group(1)
    # M81B and M81C are Auth0 arc milestones — not for Datadog/Clerk
    assert '"M81B"' not in block, "Stale M81B (Auth0 arc) in NEXT_PROVIDERS_BRIEF"
    assert '"M81C"' not in block, "Stale M81C (Auth0 arc) in NEXT_PROVIDERS_BRIEF"


def test_fe_demo_script_page_description_mentions_auth0():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    assert "Auth0" in text
    assert "M81A" in text


# ════════════════════════════════════════════════════════════════════════════
# Section H — Forbidden wording scan
# ════════════════════════════════════════════════════════════════════════════

_BACKEND_AUTH0_MODULES = [
    "app/connectors/auth0.py",
    "app/connectors/auth0_schema.py",
    "app/services/provider_capability_matrix_service.py",
    "app/services/risk_rules/auth0.py",
]

_BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _read_backend(rel: str) -> str:
    path = _BACKEND_ROOT / rel
    if not path.exists():
        pytest.skip(f"Backend module {rel!r} not found")
    return path.read_text(encoding="utf-8")


def _strip_negation_contexts(src: str) -> str:
    """Remove lines that explicitly negate a forbidden claim."""
    out = []
    for line in src.splitlines():
        low = line.lower()
        if any(
            tok in low
            for tok in (
                "does not confirm", "never assert", "never claim",
                "do not claim", "forbidden", "not confirm",
                "claim discipline", "review-safe", "without claiming",
            )
        ):
            continue
        out.append(line)
    return "\n".join(out)


@pytest.mark.parametrize("module", _BACKEND_AUTH0_MODULES)
def test_auth0_module_no_forbidden_wording(module: str):
    """No forbidden claim phrases in any Auth0 backend module."""
    text = _read_backend(module)
    stripped = _strip_negation_contexts(text).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"{module} contains forbidden phrase {phrase!r} "
            f"outside a negation context"
        )


def test_auth0_connector_has_no_jwt_shaped_strings():
    """The Auth0 connector must not contain any JWT-shaped test values (eyJ...)."""
    text = _read_backend("app/connectors/auth0.py")
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", text), (
        "auth0.py contains a JWT-shaped string (eyJ...)"
    )


def test_auth0_schema_has_no_jwt_shaped_strings():
    text = _read_backend("app/connectors/auth0_schema.py")
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", text), (
        "auth0_schema.py contains a JWT-shaped string (eyJ...)"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section — Diff tracked fields and risk classification (QA pass)
# ════════════════════════════════════════════════════════════════════════════
#
# Auth0 previously had NO entry in diff_service.py's tracked-fields dispatch
# (every auth0_ record type fell through to the Cloudflare DNS default tuple,
# so compute_diff could never detect a modified field) and NO
# risk_rules/auth0.py module at all (risk_service.py had no auth0_ dispatch
# branch, so every Auth0 change silently fell through to the Cloudflare DNS
# classifier) — despite the provider capability matrix already claiming
# drift_diff=True and drift_risk_classification=True. Both were built during
# this QA pass, making that pre-existing capability-matrix claim actually true.


class TestAuth0DiffTrackedFields:
    def test_all_eight_record_types_have_tracked_fields_entries(self):
        from app.connectors.auth0_schema import AUTH0_RECORD_TYPES
        from app.services.diff_service import _AUTH0_TRACKED_FIELDS_BY_TYPE

        for record_type in AUTH0_RECORD_TYPES:
            assert record_type in _AUTH0_TRACKED_FIELDS_BY_TYPE, (
                f"{record_type!r} has no tracked-fields entry — modified-field "
                "changes for this record type will never be detected by compute_diff"
            )

    def test_tracked_fields_dispatch_uses_auth0_table_not_cloudflare_default(self):
        from app.connectors.auth0_schema import AUTH0_RECORD_TYPES
        from app.services.diff_service import _tracked_fields_for, _TRACKED_FIELDS

        for record_type in AUTH0_RECORD_TYPES:
            fields = _tracked_fields_for({"record_type": record_type})
            assert fields != _TRACKED_FIELDS, (
                f"{record_type!r} is falling through to the Cloudflare DNS "
                "default tracked-fields tuple instead of its own Auth0 fields"
            )
            assert fields, f"{record_type!r} resolved to an empty tracked-fields tuple"

    def test_jwt_alg_change_produces_drift_change(self):
        """jwt_alg RS256 -> HS256 must surface as a Change."""
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        def _application_record(jwt_alg: str) -> dict:
            return {
                "record_type": "auth0_application",
                "provider": "auth0",
                "record_id": "client_abc",
                "client_id": "client_abc",
                "name": "test-app",
                "app_type": "regular_web",
                "is_first_party": True,
                "grant_types_summary": "authorization_code",
                "callbacks_count": 1,
                "allowed_logout_urls_count": 1,
                "allowed_origins_count": 1,
                "web_origins_count": 1,
                "jwt_alg": jwt_alg,
                "oidc_conformant": True,
                "token_endpoint_auth_method": "client_secret_basic",
                "refresh_token_rotation_enabled": True,
                "refresh_token_lifetime_category": "short",
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

        prev = _mock_snapshot([_application_record("RS256")])
        new = _mock_snapshot([_application_record("HS256")])

        changes = compute_diff(prev, new)
        jwt_changes = [c for c in changes if c["field_path"] == "jwt_alg"]

        assert len(jwt_changes) == 1
        assert jwt_changes[0]["prev_value"] == "RS256"
        assert jwt_changes[0]["new_value"] == "HS256"

    def test_no_spurious_change_when_records_are_identical(self):
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        record = {
            "record_type": "auth0_connection",
            "provider": "auth0",
            "record_id": "con_1",
            "connection_id": "con_1",
            "name": "database-connection",
            "strategy": "auth0",
            "enabled_clients_count": 2,
            "is_domain_connection": False,
            "password_policy_category": "good",
            "mfa_enabled": True,
        }
        prev = _mock_snapshot([dict(record)])
        new = _mock_snapshot([dict(record)])

        assert compute_diff(prev, new) == []

    def test_every_tracked_field_classifies_without_error_or_invalid_severity(self):
        """Every field in _AUTH0_TRACKED_FIELDS_BY_TYPE must be classifiable:
        classify_auth0_change must not raise, and must return one of the
        three known severities, for a representative modified change on
        each tracked field of each record type."""
        from app.services.diff_service import _AUTH0_TRACKED_FIELDS_BY_TYPE
        from app.services.risk_rules.auth0 import classify_auth0_change

        for record_type, fields in _AUTH0_TRACKED_FIELDS_BY_TYPE.items():
            for field in fields:
                change = {
                    "change_type": "modified",
                    "field_path": field,
                    "prev_value": 1,
                    "new_value": 2,
                    "provider_metadata": {"record_type": record_type},
                }
                level, reason = classify_auth0_change(change)
                assert level in ("low", "medium", "high"), (
                    f"{record_type}.{field} returned invalid severity {level!r}"
                )
                assert isinstance(reason, str) and reason, (
                    f"{record_type}.{field} returned an empty reason string"
                )


class TestAuth0RiskClassifier:
    def _make_change(
        self,
        record_type: str,
        field_path: str = "",
        change_type: str = "modified",
        prev_value: Any = None,
        new_value: Any = None,
        record_id: str = "",
    ) -> dict:
        pm = {"record_type": record_type}
        if record_id:
            pm["record_id"] = record_id
        return {
            "provider_metadata": pm,
            "field_path": field_path,
            "change_type": change_type,
            "prev_value": prev_value,
            "new_value": new_value,
        }

    def test_risk_service_dispatches_auth0_to_auth0_classifier(self):
        """Regression guard: risk_service.py must route auth0_ record types
        to classify_auth0_change, not silently fall through to the
        Cloudflare DNS classifier (the exact bug this QA pass found and
        fixed)."""
        from app.services.risk_service import classify_change

        change = self._make_change(
            "auth0_application", "grant_password_enabled",
            prev_value=False, new_value=True,
        )
        mock_change = MagicMock()
        mock_change.provider_metadata = change["provider_metadata"]
        mock_change.field_path = change["field_path"]
        mock_change.change_type = change["change_type"]
        mock_change.prev_value = change["prev_value"]
        mock_change.new_value = change["new_value"]
        level, reason = classify_change(mock_change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"
        assert "auth0" in reason.lower()

    def test_password_grant_enabled_is_high(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "grant_password_enabled", prev_value=False, new_value=True,
        )
        level, reason = classify_auth0_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_password_grant_disabled_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "grant_password_enabled", prev_value=True, new_value=False,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_implicit_grant_enabled_is_high(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "grant_implicit_enabled", prev_value=False, new_value=True,
        )
        level, reason = classify_auth0_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_wildcard_callback_present_is_high(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "wildcard_callback_present", prev_value=False, new_value=True,
        )
        level, reason = classify_auth0_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_wildcard_callback_removed_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "wildcard_callback_present", prev_value=True, new_value=False,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_weak_jwt_alg_is_high(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "jwt_alg", prev_value="RS256", new_value="HS256",
        )
        level, reason = classify_auth0_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_jwt_alg_strengthened_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "jwt_alg", prev_value="HS256", new_value="RS256",
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_refresh_token_rotation_disabled_is_medium(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "refresh_token_rotation_enabled", prev_value=True, new_value=False,
        )
        level, reason = classify_auth0_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_refresh_token_rotation_enabled_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "refresh_token_rotation_enabled", prev_value=False, new_value=True,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_dynamic_client_registration_enabled_is_high(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_tenant_settings", "flag_enable_dynamic_client_registration",
            prev_value=False, new_value=True,
        )
        level, reason = classify_auth0_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_tenant_session_lifetime_extended_is_medium(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_tenant_settings", "session_lifetime_category",
            prev_value="standard", new_value="extended",
        )
        level, reason = classify_auth0_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_connection_weak_password_policy_is_high(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_connection", "password_policy_category", prev_value="excellent", new_value="fair",
        )
        level, reason = classify_auth0_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_connection_password_policy_unset_is_high(self):
        """Matches security_rules/auth0.py's explicit unknown-posture rule:
        a database connection's password policy being unset (None) is
        itself treated as 'not configured' and rated the same as weak."""
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_connection", "password_policy_category", prev_value="good", new_value=None,
        )
        level, reason = classify_auth0_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_connection_password_policy_strengthened_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_connection", "password_policy_category", prev_value="fair", new_value="excellent",
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_connection_mfa_disabled_is_high(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_connection", "mfa_enabled", prev_value=True, new_value=False,
        )
        level, reason = classify_auth0_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_resource_server_rbac_disabled_is_medium(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_resource_server", "rbac_enabled", prev_value=True, new_value=False,
        )
        level, reason = classify_auth0_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_resource_server_offline_access_enabled_is_medium(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_resource_server", "allow_offline_access", prev_value=False, new_value=True,
        )
        level, reason = classify_auth0_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_resource_server_weak_signing_alg_is_high(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_resource_server", "signing_alg", prev_value="RS256", new_value="HS256",
        )
        level, reason = classify_auth0_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_custom_domain_not_ready_is_medium(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_custom_domain", "status", prev_value="ready", new_value="pending_verification",
        )
        level, reason = classify_auth0_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_custom_domain_ready_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_custom_domain", "status", prev_value="pending_verification", new_value="ready",
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_rule_disabled_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_rule", "enabled", prev_value=True, new_value=False,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_mfa_factor_strong_disabled_is_medium(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_mfa_factor", "enabled", prev_value=True, new_value=False,
            record_id="auth0_mfa_factor_otp",
        )
        level, reason = classify_auth0_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_mfa_factor_non_strong_disabled_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_mfa_factor", "enabled", prev_value=True, new_value=False,
            record_id="auth0_mfa_factor_recovery-code",
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_callbacks_count_increase_while_already_broad_is_medium(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "callbacks_count", prev_value=15, new_value=20,
        )
        level, reason = classify_auth0_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_callbacks_count_decrease_while_still_broad_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "callbacks_count", prev_value=20, new_value=15,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_grant_types_count_increase_while_already_broad_is_medium(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "grant_types_count", prev_value=5, new_value=6,
        )
        level, reason = classify_auth0_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_unknown_record_type_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change("auth0_unknown_surface", "some_field", prev_value=1, new_value=2)
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_unknown_transitions_never_produce_high(self):
        from app.services.risk_rules.auth0 import classify_auth0_change

        unknown_cases = [
            ("auth0_application", "grant_password_enabled", False, None),
            ("auth0_application", "grant_implicit_enabled", False, None),
            ("auth0_application", "wildcard_callback_present", False, None),
            ("auth0_application", "jwt_alg", "RS256", None),
            ("auth0_tenant_settings", "flag_enable_dynamic_client_registration", False, None),
            ("auth0_connection", "mfa_enabled", True, None),
            ("auth0_resource_server", "signing_alg", "RS256", None),
        ]
        for record_type, field, prev, new in unknown_cases:
            change = self._make_change(record_type, field, prev_value=prev, new_value=new)
            level, reason = classify_auth0_change(change)
            assert level != "high", (
                f"{record_type}.{field} unknown transition produced 'high': {reason!r}"
            )

    def test_count_unknown_not_treated_as_zero(self):
        """A count field's unknown value must not be treated as an explicit
        zero — this is the exact bug fixed in PagerDuty's classification-QA
        pass, guarded against here from the start."""
        from app.services.risk_rules.auth0 import classify_auth0_change

        change = self._make_change(
            "auth0_application", "callbacks_count", prev_value=15, new_value=None,
        )
        level, reason = classify_auth0_change(change)
        assert level == "low", f"Expected low, got {level!r}: {reason}"
        assert "unknown or missing" in reason.lower()

    def test_classifier_reads_real_compute_diff_dict_shape_not_a_mock(self):
        """Regression guard against the exact old_value/prev_value bug class
        found in Terraform Cloud's first QA pass: builds a plain dict shaped
        EXACTLY like compute_diff's real output (prev_value/new_value/
        field_path/change_type/provider_metadata), not a MagicMock, to prove
        the classifier reads the real field name."""
        from app.services.risk_rules.auth0 import classify_auth0_change

        real_shaped_change = {
            "change_type": "modified",
            "field_path": "grant_password_enabled",
            "prev_value": False,
            "new_value": True,
            "provider_metadata": {"record_type": "auth0_application"},
        }
        level, reason = classify_auth0_change(real_shaped_change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_no_forbidden_wording_in_reasons(self):
        from app.services.risk_rules.auth0 import classify_auth0_change

        FORBIDDEN = [
            "breach", "compromise", "attacker", "leaked", "unauthorized access",
            "account takeover", "credential exposed", "credentials exposed",
            "token exposed", "tokens exposed", "secret exposed", "secrets exposed",
            "user data exposed", "auth0 data exposed", "data exposed",
            "exfiltration", "stolen", "fraud", "attack detected",
        ]
        test_changes = [
            self._make_change("auth0_application", "grant_password_enabled", prev_value=False, new_value=True),
            self._make_change("auth0_application", "wildcard_callback_present", prev_value=False, new_value=True),
            self._make_change("auth0_application", "jwt_alg", prev_value="RS256", new_value="HS256"),
            self._make_change("auth0_connection", "password_policy_category", prev_value="good", new_value="fair"),
            self._make_change("auth0_connection", "mfa_enabled", prev_value=True, new_value=False),
            self._make_change("auth0_resource_server", "rbac_enabled", prev_value=True, new_value=False),
            self._make_change("auth0_tenant_settings", "flag_enable_dynamic_client_registration", prev_value=False, new_value=True),
        ]
        for change in test_changes:
            _, reason = classify_auth0_change(change)
            reason_lower = reason.lower()
            for phrase in FORBIDDEN:
                assert phrase not in reason_lower, (
                    f"Forbidden phrase {phrase!r} found in risk reason: {reason!r}"
                )


# ════════════════════════════════════════════════════════════════════════════
# Section — Change-classification QA pass (dedicated follow-up)
# ════════════════════════════════════════════════════════════════════════════
#
# Two bugs found and fixed in this pass:
#
# 1. auth0_application.allowed_logout_urls_count was tracked in
#    _AUTH0_TRACKED_FIELDS_BY_TYPE but had no branch in risk_rules/auth0.py
#    at all — it silently fell through to the bare "configuration field
#    '...' changed." fallback instead of being grouped with its sibling
#    count fields. Severity was unaffected (still "low" either way), but
#    the field is now named explicitly.
#
# 2. grant_client_credentials_enabled: True -> False previously returned
#    "medium" unconditionally. The backing Finding
#    (auth0_application_public_client_credentials_enabled, high) only
#    fires when this grant is COMBINED with a public/client-side app_type
#    or token_endpoint_auth_method="none" — client_credentials is Auth0's
#    standard, expected grant for confidential machine-to-machine
#    applications, which is the common case. Defaulting to "medium" on
#    every enablement would over-alert on normal M2M configuration.
#    Downgraded to "low" (a Change-only, generic signal), consistent with
#    how grant_refresh_token_enabled and grant_authorization_code_enabled
#    are already treated — the Finding layer (which can see app_type)
#    remains the source of truth for the genuinely risky combination.


class TestAuth0ChangeClassificationQA:
    def _make_change(
        self,
        record_type: str,
        field_path: str = "",
        change_type: str = "modified",
        prev_value: Any = None,
        new_value: Any = None,
        record_id: str = "",
    ) -> dict:
        pm = {"record_type": record_type}
        if record_id:
            pm["record_id"] = record_id
        return {
            "provider_metadata": pm,
            "field_path": field_path,
            "change_type": change_type,
            "prev_value": prev_value,
            "new_value": new_value,
        }

    def test_allowed_logout_urls_count_is_explicitly_named_not_bare_fallback(self):
        """Regression test for the allowed_logout_urls_count fall-through
        bug fixed in this classification-QA pass."""
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "allowed_logout_urls_count", prev_value=1, new_value=2,
        )
        level, reason = classify_auth0_change(change)
        assert level == "low"
        assert "allowed logout urls count" in reason.lower()
        assert "configuration field 'allowed_logout_urls_count'" not in reason.lower()

    def test_client_credentials_grant_enabled_is_low_not_medium(self):
        """Regression test for the grant_client_credentials_enabled
        over-alerting bug fixed in this classification-QA pass: enabling
        this grant is normal/expected for confidential M2M applications,
        so it must not default to medium without app_type evidence."""
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "grant_client_credentials_enabled", prev_value=False, new_value=True,
        )
        level, reason = classify_auth0_change(change)
        assert level == "low", f"Expected low, got {level!r}: {reason}"

    def test_client_credentials_grant_disabled_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "grant_client_credentials_enabled", prev_value=True, new_value=False,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    # ── Tenant settings (category A) ─────────────────────────────────────────

    def test_tenant_dynamic_client_registration_disabled_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_tenant_settings", "flag_enable_dynamic_client_registration",
            prev_value=True, new_value=False,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_tenant_session_lifetime_restored_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_tenant_settings", "session_lifetime_category",
            prev_value="extended", new_value="standard",
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_tenant_idle_session_lifetime_extended_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_tenant_settings", "idle_session_lifetime_category",
            prev_value="standard", new_value="extended",
        )
        level, reason = classify_auth0_change(change)
        assert level == "low", f"Expected low, got {level!r}: {reason}"

    # ── Applications / clients (category B) ──────────────────────────────────

    def test_oidc_conformant_restored_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "oidc_conformant", prev_value=False, new_value=True,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_token_endpoint_auth_none_restored_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "token_endpoint_auth_method",
            prev_value="none", new_value="client_secret_basic",
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_wildcard_allowed_origin_removed_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "wildcard_allowed_origin_present", prev_value=True, new_value=False,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_wildcard_logout_url_present_is_medium(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "wildcard_logout_url_present", prev_value=False, new_value=True,
        )
        level, reason = classify_auth0_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_callbacks_missing_https_restored_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "callbacks_missing_https", prev_value=True, new_value=False,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_web_origins_count_increase_while_already_broad_is_medium(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "web_origins_count", prev_value=15, new_value=20,
        )
        level, reason = classify_auth0_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_grant_types_count_decrease_while_still_broad_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_application", "grant_types_count", prev_value=8, new_value=6,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    # ── Connections (category C) ─────────────────────────────────────────────

    def test_connection_mfa_enabled_restored_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_connection", "mfa_enabled", prev_value=False, new_value=True,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_connection_enabled_clients_count_zero_is_low_not_error(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_connection", "enabled_clients_count", prev_value=3, new_value=0,
        )
        level, reason = classify_auth0_change(change)
        assert level == "low", f"Expected low, got {level!r}: {reason}"

    # ── Resource servers / APIs (category D) ─────────────────────────────────

    def test_resource_server_rbac_restored_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_resource_server", "rbac_enabled", prev_value=False, new_value=True,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_resource_server_offline_access_disabled_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_resource_server", "allow_offline_access", prev_value=True, new_value=False,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_resource_server_signing_alg_strengthened_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_resource_server", "signing_alg", prev_value="HS256", new_value="RS256",
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_resource_server_token_lifetime_restored_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_resource_server", "token_lifetime_category", prev_value="extended", new_value="short",
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    # ── Custom domains (category E) ──────────────────────────────────────────

    def test_custom_domain_provisioning_is_medium(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_custom_domain", "status", prev_value="ready", new_value="provisioning",
        )
        level, reason = classify_auth0_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_custom_domain_tls_policy_restored_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_custom_domain", "tls_policy_category", prev_value="compatible", new_value="recommended",
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    # ── Rules / actions (category F) ─────────────────────────────────────────

    def test_rule_enabled_restored_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_rule", "enabled", prev_value=False, new_value=True,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    def test_action_secrets_count_real_zero_is_low_not_error(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_action", "secrets_count", prev_value=2, new_value=0,
        )
        level, reason = classify_auth0_change(change)
        assert level == "low", f"Expected low, got {level!r}: {reason}"

    def test_action_deployed_version_restored_is_low(self):
        from app.services.risk_rules.auth0 import classify_auth0_change
        change = self._make_change(
            "auth0_action", "deployed_version_present", prev_value=False, new_value=True,
        )
        level, _ = classify_auth0_change(change)
        assert level == "low"

    # ── Broader unknown-transition sweep across every high/medium field ─────

    def test_broader_unknown_transition_sweep_never_produces_high_or_overstated_medium(self):
        """Extends the existing unknown-transition sweep to every field this
        pass identified as carrying a high or medium severity, proving
        _is_falsy_explicit()/_is_truthy() correctly distinguish None from an
        explicit False across the whole module, not just the fields already
        covered by the original detection-QA pass."""
        from app.services.risk_rules.auth0 import classify_auth0_change

        cases = [
            ("auth0_tenant_settings", "session_lifetime_category", "standard", None),
            ("auth0_tenant_settings", "flag_enable_dynamic_client_registration", False, None),
            ("auth0_application", "oidc_conformant", True, None),
            ("auth0_application", "jwt_alg", "RS256", None),
            ("auth0_application", "refresh_token_rotation_enabled", True, None),
            ("auth0_application", "wildcard_callback_present", False, None),
            ("auth0_application", "wildcard_allowed_origin_present", False, None),
            ("auth0_application", "token_endpoint_auth_method", "client_secret_basic", None),
            # NOTE: auth0_connection.password_policy_category is deliberately
            # excluded here — None is an intentional exception (see
            # test_connection_password_policy_unset_is_high) that mirrors
            # the Security Finding's own explicit "unset is itself weak"
            # design, not an unknown-overstatement bug.
            ("auth0_connection", "mfa_enabled", True, None),
            ("auth0_resource_server", "rbac_enabled", True, None),
            ("auth0_resource_server", "signing_alg", "RS256", None),
            ("auth0_resource_server", "allow_offline_access", False, None),
            ("auth0_custom_domain", "status", "ready", None),
            ("auth0_mfa_factor", "enabled", True, None),
        ]
        for record_type, field, prev, new in cases:
            change = self._make_change(record_type, field, prev_value=prev, new_value=new)
            level, reason = classify_auth0_change(change)
            assert level != "high", (
                f"{record_type}.{field} unknown transition produced 'high': {reason!r}"
            )
            reason_lower = reason.lower()
            assert "disabled" not in reason_lower or "unknown" in reason_lower or "missing" in reason_lower, (
                f"{record_type}.{field} unknown transition may overstate certainty: {reason!r}"
            )

    def test_generic_fallback_never_used_for_security_sensitive_fields(self):
        """Every field this pass classified as high/medium-capable (MFA,
        weak JWT/signing algorithm, wildcard callback/origin, password
        policy, dynamic client registration, RBAC, custom domain status)
        must resolve through a field-specific branch, not the bare
        '<record type> configuration field '...' changed.' fallback used
        for purely cosmetic/metadata fields."""
        from app.services.risk_rules.auth0 import classify_auth0_change

        security_sensitive = [
            ("auth0_tenant_settings", "flag_enable_dynamic_client_registration", False, True),
            ("auth0_application", "grant_password_enabled", False, True),
            ("auth0_application", "wildcard_callback_present", False, True),
            ("auth0_application", "jwt_alg", "RS256", "HS256"),
            ("auth0_connection", "password_policy_category", "good", "fair"),
            ("auth0_connection", "mfa_enabled", True, False),
            ("auth0_resource_server", "rbac_enabled", True, False),
            ("auth0_resource_server", "signing_alg", "RS256", "HS256"),
            ("auth0_custom_domain", "status", "ready", "pending_verification"),
            ("auth0_mfa_factor", "enabled", True, False),
        ]
        for record_type, field, prev, new in security_sensitive:
            change = self._make_change(record_type, field, prev_value=prev, new_value=new)
            _, reason = classify_auth0_change(change)
            assert "configuration field" not in reason.lower(), (
                f"{record_type}.{field} used the generic bare fallback instead of "
                f"a field-specific branch: {reason!r}"
            )
