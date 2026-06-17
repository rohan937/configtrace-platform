"""M81C — Auth0 OAuth/application risk expansion tests.

Verifies the 15 new Auth0 security rules added in M81C, their registration
across rule registry / confidence / pack / coverage tables, frontend catalog
parity, capability matrix and expansion framework updates, and safe schema/
connector expansions.

Privacy guarantees verified by these tests
------------------------------------------
- Rule evidence never contains client secrets, management tokens, access
  tokens, refresh tokens, ID tokens, JWTs, private keys, authorization
  headers, raw callback/logout/origin URLs, audience URIs, custom domain
  names, action secrets, user emails/names/IDs, or any customer PII.
- Wildcard, localhost, and HTTPS posture rules use boolean fields only;
  no raw URL strings appear in findings.
- Grant type rules use boolean/count fields only; no token values appear.
- token_endpoint_auth_method is a safe category string, not a credential.

Sections
--------
  A. Rule keys / registration parity (registry, confidence, pack, coverage,
     frontend catalog, AUTH0_RULE_KEYS set)
  B. Schema/connector expansions — safe fields only
  C. Grant type posture rules
  D. Wildcard posture rules
  E. Localhost posture rules
  F. HTTPS posture rules
  G. Public client / token endpoint posture rules
  H. No-trigger on healthy records
  I. Privacy / evidence-field scan (all 15 new rules)
  J. Capability matrix and provider expansion framework
  K. Forbidden wording in Auth0 security rules module
  L. No secret-shaped strings in backend/app and frontend/src
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Any

import pytest

from app.connectors.auth0_schema import AUTH0_APPLICATION
from app.services.security_rules.auth0 import AUTH0_RULE_KEYS, evaluate

# ── Expected M81C rule keys ────────────────────────────────────────────────────

M81C_RULE_KEYS = frozenset({
    # Grant type posture
    "auth0_application_password_grant_enabled",
    "auth0_application_implicit_grant_enabled",
    "auth0_application_public_client_credentials_enabled",
    "auth0_application_refresh_grant_without_rotation",
    "auth0_application_many_grant_types",
    "auth0_application_device_code_grant_enabled",
    # Wildcard posture
    "auth0_application_wildcard_callback",
    "auth0_application_wildcard_allowed_origin",
    "auth0_application_wildcard_logout_url",
    # Localhost posture
    "auth0_application_localhost_callback",
    "auth0_application_localhost_origin",
    # HTTPS posture
    "auth0_application_callback_missing_https",
    "auth0_application_origin_missing_https",
    # Public client / token endpoint posture
    "auth0_public_client_refresh_tokens_enabled",
    "auth0_application_token_endpoint_auth_none",
})

# Forbidden claim wording (M75A)
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# Fields that must never appear in rule evidence
FORBIDDEN_EVIDENCE_KEYS = frozenset({
    "client_secret", "management_api_token", "access_token",
    "refresh_token", "id_token", "jwt", "signing_key", "private_key",
    "authorization", "bearer",
    "callback_url", "callback_urls", "logout_url", "logout_urls",
    "allowed_origin", "allowed_origins_list", "web_origins_list",
    "audience", "audience_uri", "identifier",
    "domain_name", "custom_domain_name",
    "script", "code", "secret_value", "secret_name",
    "email", "user_id", "user_name", "ip_address", "session_id",
    "recovery_code", "mfa_enrollment",
    "saml_cert", "saml_key", "ldap_password",
    "webhook_secret", "verification_token",
    "password", "credential",
})

# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_app(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a minimal healthy auth0_application record."""
    base: dict[str, Any] = {
        "record_type": AUTH0_APPLICATION,
        "record_id": "AUTH0_TEST_CLIENT_ID",
        "provider_resource_id": "clients/AUTH0_TEST_CLIENT_ID",
        "client_id": "AUTH0_TEST_CLIENT_ID",
        "name": "Test App",
        "app_type": "regular_web",
        "is_first_party": True,
        "grant_types_summary": "authorization_code,refresh_token",
        "callbacks_count": 2,
        "allowed_logout_urls_count": 1,
        "allowed_origins_count": 1,
        "web_origins_count": 1,
        "jwt_alg": "RS256",
        "oidc_conformant": True,
        "token_endpoint_auth_method": "client_secret_basic",
        "refresh_token_rotation_enabled": True,
        "refresh_token_lifetime_category": "standard",
        # M81C safe fields
        "grant_types_count": 2,
        "grant_password_enabled": False,
        "grant_implicit_enabled": False,
        "grant_client_credentials_enabled": False,
        "grant_authorization_code_enabled": True,
        "grant_refresh_token_enabled": True,
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
    if overrides:
        base.update(overrides)
    return base


def _finding_keys(findings: list) -> set[str]:
    return {f.rule_key for f in findings}


def _evidence_of(findings: list, rule_key: str) -> dict:
    for f in findings:
        if f.rule_key == rule_key:
            return f.evidence
    return {}


# ── Section A: Rule key / registration parity ─────────────────────────────────


class TestRuleKeyRegistration:
    def test_m81c_keys_in_auth0_rule_keys(self):
        assert M81C_RULE_KEYS.issubset(AUTH0_RULE_KEYS), (
            f"Missing from AUTH0_RULE_KEYS: {M81C_RULE_KEYS - AUTH0_RULE_KEYS}"
        )

    def test_m81c_keys_in_known_rule_keys(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        missing = M81C_RULE_KEYS - KNOWN_RULE_KEYS
        assert not missing, f"Missing from KNOWN_RULE_KEYS: {missing}"

    def test_m81c_keys_in_confidence_registry(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        missing = M81C_RULE_KEYS - set(RULE_CONFIDENCE.keys())
        assert not missing, f"Missing from RULE_CONFIDENCE: {missing}"

    def test_m81c_keys_in_rule_pack(self):
        from app.services.security_rule_pack import _RULE_META
        missing = M81C_RULE_KEYS - set(_RULE_META.keys())
        assert not missing, f"Missing from _RULE_META: {missing}"

    def test_m81c_keys_in_coverage_service(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        missing = M81C_RULE_KEYS - set(RULE_RECORD_TYPES.keys())
        assert not missing, f"Missing from RULE_RECORD_TYPES: {missing}"

    def test_coverage_service_maps_to_auth0_application(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in M81C_RULE_KEYS:
            assert "auth0_application" in RULE_RECORD_TYPES[key], (
                f"{key} should map to auth0_application"
            )

    def test_m81c_keys_in_frontend_catalog(self):
        catalog_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"
        )
        catalog_text = catalog_path.read_text()
        for key in M81C_RULE_KEYS:
            assert key in catalog_text, f"Frontend catalog missing: {key}"

    def test_m81b_keys_still_present(self):
        """M81B rules must remain intact."""
        m81b_keys = frozenset({
            "auth0_tenant_session_lifetime_extended",
            "auth0_application_no_callbacks",
            "auth0_application_weak_jwt_algorithm",
            "auth0_refresh_token_rotation_disabled",
            "auth0_connection_weak_password_policy",
            "auth0_resource_server_rbac_disabled",
            "auth0_mfa_factor_disabled",
            "auth0_custom_domain_not_ready",
        })
        assert m81b_keys.issubset(AUTH0_RULE_KEYS)


# ── Section B: Schema/connector safe expansions ───────────────────────────────


class TestSchemaConnectorExpansions:
    """Verify the safe M81C fields are produced by the connector normalizer."""

    def test_normalize_application_grant_booleans(self):
        from app.connectors.auth0 import Auth0Connector
        raw = {
            "client_id": "AUTH0_TEST_CLIENT_ID",
            "name": "Test",
            "app_type": "regular_web",
            "is_first_party": True,
            "grant_types": ["authorization_code", "refresh_token", "password"],
            "callbacks": ["https://example.com/callback"],
            "allowed_logout_urls": ["https://example.com/logout"],
            "allowed_origins": ["https://example.com"],
            "web_origins": ["https://example.com"],
            "jwt_configuration": {"alg": "RS256"},
            "oidc_conformant": True,
            "token_endpoint_auth_method": "client_secret_basic",
            "refresh_token": {"rotation_type": "rotating", "token_lifetime": 3600},
        }
        rec = Auth0Connector._normalize_application(raw)
        assert rec is not None
        assert rec["grant_types_count"] == 3
        assert rec["grant_password_enabled"] is True
        assert rec["grant_refresh_token_enabled"] is True
        assert rec["grant_authorization_code_enabled"] is True
        assert rec["grant_implicit_enabled"] is False
        assert rec["grant_client_credentials_enabled"] is False
        assert rec["grant_device_code_enabled"] is False

    def test_normalize_application_device_code_grant(self):
        from app.connectors.auth0 import Auth0Connector
        raw = {
            "client_id": "AUTH0_TEST_CLIENT_ID",
            "name": "TV App",
            "app_type": "native",
            "grant_types": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "callbacks": [],
            "allowed_logout_urls": [],
            "allowed_origins": [],
            "web_origins": [],
        }
        rec = Auth0Connector._normalize_application(raw)
        assert rec is not None
        assert rec["grant_device_code_enabled"] is True
        assert rec["grant_types_count"] == 2

    def test_normalize_application_wildcard_booleans(self):
        from app.connectors.auth0 import Auth0Connector
        raw = {
            "client_id": "AUTH0_TEST_CLIENT_ID",
            "name": "Wild App",
            "app_type": "spa",
            "grant_types": ["authorization_code"],
            "callbacks": ["https://*.example.com/callback"],
            "allowed_logout_urls": ["https://*.example.com/logout"],
            "allowed_origins": ["https://*.example.com"],
            "web_origins": ["https://example.com"],
        }
        rec = Auth0Connector._normalize_application(raw)
        assert rec is not None
        assert rec["wildcard_callback_present"] is True
        assert rec["wildcard_logout_url_present"] is True
        assert rec["wildcard_allowed_origin_present"] is True
        # Raw URLs must NOT appear in the record
        for key in ("callbacks", "allowed_logout_urls", "allowed_origins", "web_origins"):
            assert key not in rec

    def test_normalize_application_localhost_booleans(self):
        from app.connectors.auth0 import Auth0Connector
        raw = {
            "client_id": "AUTH0_TEST_CLIENT_ID",
            "name": "Dev App",
            "app_type": "spa",
            "grant_types": ["authorization_code"],
            "callbacks": ["http://localhost:3000/callback", "https://example.com/cb"],
            "allowed_logout_urls": ["https://example.com/logout"],
            "allowed_origins": ["http://127.0.0.1:3000"],
            "web_origins": [],
        }
        rec = Auth0Connector._normalize_application(raw)
        assert rec is not None
        assert rec["localhost_callback_present"] is True
        assert rec["localhost_origin_present"] is True

    def test_normalize_application_https_booleans(self):
        from app.connectors.auth0 import Auth0Connector
        raw = {
            "client_id": "AUTH0_TEST_CLIENT_ID",
            "name": "HTTP App",
            "app_type": "regular_web",
            "grant_types": ["authorization_code"],
            "callbacks": ["http://api.example.com/callback"],
            "allowed_logout_urls": ["https://example.com/logout"],
            "allowed_origins": ["http://api.example.com"],
            "web_origins": [],
        }
        rec = Auth0Connector._normalize_application(raw)
        assert rec is not None
        assert rec["callbacks_missing_https"] is True
        assert rec["allowed_origins_missing_https"] is True

    def test_localhost_not_flagged_as_missing_https(self):
        from app.connectors.auth0 import Auth0Connector
        raw = {
            "client_id": "AUTH0_TEST_CLIENT_ID",
            "name": "Dev App",
            "app_type": "spa",
            "grant_types": ["authorization_code"],
            "callbacks": ["http://localhost:3000/callback"],
            "allowed_logout_urls": [],
            "allowed_origins": ["http://localhost:3000"],
            "web_origins": [],
        }
        rec = Auth0Connector._normalize_application(raw)
        assert rec is not None
        # localhost http:// should NOT trigger callbacks_missing_https
        assert rec["callbacks_missing_https"] is False
        assert rec["allowed_origins_missing_https"] is False
        # but localhost_present should trigger
        assert rec["localhost_callback_present"] is True
        assert rec["localhost_origin_present"] is True

    def test_no_raw_url_strings_in_record(self):
        from app.connectors.auth0 import Auth0Connector
        raw = {
            "client_id": "AUTH0_TEST_CLIENT_ID",
            "name": "App",
            "app_type": "spa",
            "grant_types": ["authorization_code"],
            "callbacks": ["https://example.com/callback"],
            "allowed_logout_urls": ["https://example.com/logout"],
            "allowed_origins": ["https://example.com"],
            "web_origins": ["https://example.com"],
        }
        rec = Auth0Connector._normalize_application(raw)
        assert rec is not None
        # No field should contain a raw URL string
        for key, val in rec.items():
            if isinstance(val, str):
                assert not val.startswith("http://") and not val.startswith("https://"), (
                    f"Raw URL found in record field '{key}': {val!r}"
                )

    def test_no_grant_token_values_in_record(self):
        from app.connectors.auth0 import Auth0Connector
        raw = {
            "client_id": "AUTH0_TEST_CLIENT_ID",
            "name": "App",
            "app_type": "regular_web",
            "grant_types": ["authorization_code", "refresh_token", "password"],
            "callbacks": [],
            "allowed_logout_urls": [],
            "allowed_origins": [],
            "web_origins": [],
        }
        rec = Auth0Connector._normalize_application(raw)
        assert rec is not None
        for key, val in rec.items():
            if isinstance(val, str):
                # No token values or JWT-shaped strings
                assert not re.match(r"eyJ[A-Za-z0-9_-]{10,}", val), (
                    f"JWT-shaped value in field '{key}'"
                )


# ── Section C: Grant type posture rules ───────────────────────────────────────


class TestGrantTypeRules:
    def test_password_grant_fires(self):
        rec = _make_app({"grant_password_enabled": True})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_password_grant_enabled" in keys

    def test_password_grant_no_fire_when_false(self):
        rec = _make_app({"grant_password_enabled": False})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_password_grant_enabled" not in keys

    def test_implicit_grant_fires(self):
        rec = _make_app({"grant_implicit_enabled": True})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_implicit_grant_enabled" in keys

    def test_implicit_grant_no_fire_when_false(self):
        rec = _make_app({"grant_implicit_enabled": False})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_implicit_grant_enabled" not in keys

    def test_public_client_credentials_fires_spa(self):
        rec = _make_app({
            "app_type": "spa",
            "grant_client_credentials_enabled": True,
            "token_endpoint_auth_method": "none",
        })
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_public_client_credentials_enabled" in keys

    def test_public_client_credentials_fires_native(self):
        rec = _make_app({
            "app_type": "native",
            "grant_client_credentials_enabled": True,
        })
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_public_client_credentials_enabled" in keys

    def test_public_client_credentials_fires_auth_none(self):
        # non-interactive app type but token_endpoint_auth_method=none
        rec = _make_app({
            "app_type": "non_interactive",
            "grant_client_credentials_enabled": True,
            "token_endpoint_auth_method": "none",
        })
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_public_client_credentials_enabled" in keys

    def test_public_client_credentials_no_fire_confidential(self):
        # regular_web with client_secret_basic → confidential, no fire
        rec = _make_app({
            "app_type": "regular_web",
            "grant_client_credentials_enabled": True,
            "token_endpoint_auth_method": "client_secret_basic",
        })
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_public_client_credentials_enabled" not in keys

    def test_refresh_grant_without_rotation_fires(self):
        rec = _make_app({
            "grant_refresh_token_enabled": True,
            "refresh_token_rotation_enabled": False,
        })
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_refresh_grant_without_rotation" in keys

    def test_refresh_grant_without_rotation_no_fire_when_rotating(self):
        rec = _make_app({
            "grant_refresh_token_enabled": True,
            "refresh_token_rotation_enabled": True,
        })
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_refresh_grant_without_rotation" not in keys

    def test_refresh_grant_without_rotation_no_fire_no_grant(self):
        rec = _make_app({
            "grant_refresh_token_enabled": False,
            "refresh_token_rotation_enabled": False,
        })
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_refresh_grant_without_rotation" not in keys

    def test_many_grant_types_fires(self):
        rec = _make_app({"grant_types_count": 5})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_many_grant_types" in keys

    def test_many_grant_types_no_fire_at_threshold(self):
        rec = _make_app({"grant_types_count": 4})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_many_grant_types" not in keys

    def test_many_grant_types_no_fire_below_threshold(self):
        rec = _make_app({"grant_types_count": 2})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_many_grant_types" not in keys

    def test_device_code_grant_fires(self):
        rec = _make_app({"grant_device_code_enabled": True})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_device_code_grant_enabled" in keys

    def test_device_code_grant_no_fire_when_false(self):
        rec = _make_app({"grant_device_code_enabled": False})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_device_code_grant_enabled" not in keys


# ── Section D: Wildcard posture rules ─────────────────────────────────────────


class TestWildcardRules:
    def test_wildcard_callback_fires(self):
        rec = _make_app({"wildcard_callback_present": True, "callbacks_count": 3})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_wildcard_callback" in keys

    def test_wildcard_callback_no_fire_when_false(self):
        rec = _make_app({"wildcard_callback_present": False})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_wildcard_callback" not in keys

    def test_wildcard_allowed_origin_fires(self):
        rec = _make_app({"wildcard_allowed_origin_present": True, "allowed_origins_count": 2})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_wildcard_allowed_origin" in keys

    def test_wildcard_allowed_origin_no_fire_when_false(self):
        rec = _make_app({"wildcard_allowed_origin_present": False})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_wildcard_allowed_origin" not in keys

    def test_wildcard_logout_url_fires(self):
        rec = _make_app({"wildcard_logout_url_present": True})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_wildcard_logout_url" in keys

    def test_wildcard_logout_url_no_fire_when_false(self):
        rec = _make_app({"wildcard_logout_url_present": False})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_wildcard_logout_url" not in keys

    def test_wildcard_evidence_uses_boolean_only(self):
        rec = _make_app({"wildcard_callback_present": True, "callbacks_count": 3})
        findings = evaluate(rec)
        ev = _evidence_of(findings, "auth0_application_wildcard_callback")
        assert ev.get("wildcard_callback_present") is True
        # Must not contain raw URL strings
        for val in ev.values():
            if isinstance(val, str):
                assert not val.startswith("http"), f"Raw URL in wildcard evidence: {val!r}"


# ── Section E: Localhost posture rules ────────────────────────────────────────


class TestLocalhostRules:
    def test_localhost_callback_fires(self):
        rec = _make_app({"localhost_callback_present": True})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_localhost_callback" in keys

    def test_localhost_callback_no_fire_when_false(self):
        rec = _make_app({"localhost_callback_present": False})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_localhost_callback" not in keys

    def test_localhost_origin_fires(self):
        rec = _make_app({"localhost_origin_present": True})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_localhost_origin" in keys

    def test_localhost_origin_no_fire_when_false(self):
        rec = _make_app({"localhost_origin_present": False})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_localhost_origin" not in keys

    def test_localhost_evidence_uses_boolean_only(self):
        rec = _make_app({"localhost_callback_present": True})
        findings = evaluate(rec)
        ev = _evidence_of(findings, "auth0_application_localhost_callback")
        assert ev.get("localhost_callback_present") is True
        # Raw URL strings (http://localhost:...) must not appear in evidence.
        # The rule key or field name strings ("localhost_callback_present") are fine.
        for val in ev.values():
            if isinstance(val, str):
                assert not val.startswith("http://localhost"), (
                    f"Raw localhost URL in evidence: {val!r}"
                )
                assert not val.startswith("https://localhost"), (
                    f"Raw localhost URL in evidence: {val!r}"
                )
                assert not val.startswith("http://127.0.0.1"), (
                    f"Raw loopback URL in evidence: {val!r}"
                )


# ── Section F: HTTPS posture rules ────────────────────────────────────────────


class TestHttpsRules:
    def test_callback_missing_https_fires(self):
        rec = _make_app({"callbacks_missing_https": True})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_callback_missing_https" in keys

    def test_callback_missing_https_no_fire_when_false(self):
        rec = _make_app({"callbacks_missing_https": False})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_callback_missing_https" not in keys

    def test_origin_missing_https_fires(self):
        rec = _make_app({"allowed_origins_missing_https": True})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_origin_missing_https" in keys

    def test_origin_missing_https_no_fire_when_false(self):
        rec = _make_app({"allowed_origins_missing_https": False})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_origin_missing_https" not in keys

    def test_https_evidence_uses_boolean_only(self):
        rec = _make_app({"callbacks_missing_https": True, "callbacks_count": 2})
        findings = evaluate(rec)
        ev = _evidence_of(findings, "auth0_application_callback_missing_https")
        assert ev.get("callbacks_missing_https") is True
        for val in ev.values():
            if isinstance(val, str):
                assert not val.startswith("http://"), (
                    f"Raw URL in HTTPS evidence: {val!r}"
                )


# ── Section G: Public client / token endpoint rules ───────────────────────────


class TestPublicClientAndTokenEndpointRules:
    def test_public_client_refresh_tokens_fires_spa(self):
        rec = _make_app({"app_type": "spa", "grant_refresh_token_enabled": True})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_public_client_refresh_tokens_enabled" in keys

    def test_public_client_refresh_tokens_fires_native(self):
        rec = _make_app({"app_type": "native", "grant_refresh_token_enabled": True})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_public_client_refresh_tokens_enabled" in keys

    def test_public_client_refresh_tokens_no_fire_regular_web(self):
        rec = _make_app({"app_type": "regular_web", "grant_refresh_token_enabled": True})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_public_client_refresh_tokens_enabled" not in keys

    def test_public_client_refresh_tokens_no_fire_no_grant(self):
        rec = _make_app({"app_type": "spa", "grant_refresh_token_enabled": False})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_public_client_refresh_tokens_enabled" not in keys

    def test_public_client_refresh_tokens_evidence_no_token_values(self):
        rec = _make_app({"app_type": "spa", "grant_refresh_token_enabled": True})
        findings = evaluate(rec)
        ev = _evidence_of(findings, "auth0_public_client_refresh_tokens_enabled")
        assert ev.get("grant_refresh_token_enabled") is True
        assert ev.get("app_type") == "spa"
        for key in ev:
            assert "token_value" not in key.lower()
            assert "access_token" not in key.lower()
            assert "refresh_token_value" not in key.lower()

    def test_token_endpoint_auth_none_fires(self):
        rec = _make_app({"token_endpoint_auth_method": "none"})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_token_endpoint_auth_none" in keys

    def test_token_endpoint_auth_none_no_fire_client_secret(self):
        rec = _make_app({"token_endpoint_auth_method": "client_secret_basic"})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_token_endpoint_auth_none" not in keys

    def test_token_endpoint_auth_none_no_fire_client_secret_post(self):
        rec = _make_app({"token_endpoint_auth_method": "client_secret_post"})
        keys = _finding_keys(evaluate(rec))
        assert "auth0_application_token_endpoint_auth_none" not in keys

    def test_token_endpoint_evidence_uses_category_string(self):
        rec = _make_app({"token_endpoint_auth_method": "none"})
        findings = evaluate(rec)
        ev = _evidence_of(findings, "auth0_application_token_endpoint_auth_none")
        assert ev.get("token_endpoint_auth_method") == "none"
        # Value must be a safe category string, never a credential
        val = ev.get("token_endpoint_auth_method", "")
        assert not re.match(r"eyJ[A-Za-z0-9_-]{10,}", val)


# ── Section H: No-trigger on healthy records ──────────────────────────────────


class TestNoTriggerOnHealthy:
    def test_healthy_app_no_m81c_findings(self):
        """A fully-healthy app record should not trigger any M81C rules."""
        rec = _make_app()
        keys = _finding_keys(evaluate(rec))
        m81c_triggered = keys & M81C_RULE_KEYS
        assert not m81c_triggered, f"Unexpected M81C findings on healthy record: {m81c_triggered}"

    def test_unknown_record_type_no_findings(self):
        assert evaluate({"record_type": "unknown_type"}) == []

    def test_non_dict_no_findings(self):
        assert evaluate("not a dict") == []  # type: ignore[arg-type]

    def test_missing_m81c_fields_no_false_positives(self):
        """Records from before M81C without the new fields should not trigger."""
        rec: dict[str, Any] = {
            "record_type": AUTH0_APPLICATION,
            "record_id": "AUTH0_TEST_CLIENT_ID",
            "provider_resource_id": "clients/AUTH0_TEST_CLIENT_ID",
            "client_id": "AUTH0_TEST_CLIENT_ID",
            "name": "Legacy App",
            "app_type": "regular_web",
            "is_first_party": True,
            "grant_types_summary": "authorization_code",
            "callbacks_count": 2,
            "allowed_logout_urls_count": 1,
            "allowed_origins_count": 1,
            "web_origins_count": 1,
            "jwt_alg": "RS256",
            "oidc_conformant": True,
            "token_endpoint_auth_method": "client_secret_basic",
            "refresh_token_rotation_enabled": True,
            "refresh_token_lifetime_category": "standard",
            # M81C fields deliberately absent — simulating pre-M81C record
        }
        findings = evaluate(rec)
        keys = _finding_keys(findings)
        m81c_triggered = keys & M81C_RULE_KEYS
        assert not m81c_triggered, (
            f"False positives from missing M81C fields: {m81c_triggered}"
        )


# ── Section I: Privacy / evidence-field scan ──────────────────────────────────


class TestPrivacyEvidenceScan:
    """Verify that no forbidden fields appear in M81C rule evidence."""

    def _all_m81c_findings(self) -> list:
        """Collect one finding per M81C rule by constructing a minimal triggering record."""
        records = [
            _make_app({"grant_password_enabled": True}),
            _make_app({"grant_implicit_enabled": True}),
            _make_app({
                "app_type": "spa",
                "grant_client_credentials_enabled": True,
                "token_endpoint_auth_method": "none",
            }),
            _make_app({
                "grant_refresh_token_enabled": True,
                "refresh_token_rotation_enabled": False,
            }),
            _make_app({"grant_types_count": 5}),
            _make_app({"grant_device_code_enabled": True}),
            _make_app({"wildcard_callback_present": True}),
            _make_app({"wildcard_allowed_origin_present": True}),
            _make_app({"wildcard_logout_url_present": True}),
            _make_app({"localhost_callback_present": True}),
            _make_app({"localhost_origin_present": True}),
            _make_app({"callbacks_missing_https": True}),
            _make_app({"allowed_origins_missing_https": True}),
            _make_app({"app_type": "spa", "grant_refresh_token_enabled": True}),
            _make_app({"token_endpoint_auth_method": "none"}),
        ]
        all_findings = []
        for rec in records:
            all_findings.extend(evaluate(rec))
        return [f for f in all_findings if f.rule_key in M81C_RULE_KEYS]

    def test_no_forbidden_evidence_keys(self):
        findings = self._all_m81c_findings()
        assert findings, "Expected at least one M81C finding"
        for f in findings:
            for key in f.evidence:
                assert key.lower() not in FORBIDDEN_EVIDENCE_KEYS, (
                    f"Forbidden evidence key '{key}' in finding {f.rule_key}"
                )

    def test_no_raw_url_strings_in_evidence(self):
        findings = self._all_m81c_findings()
        for f in findings:
            for key, val in f.evidence.items():
                if isinstance(val, str):
                    assert not (val.startswith("http://") or val.startswith("https://")), (
                        f"Raw URL in evidence of {f.rule_key}.{key}: {val!r}"
                    )

    def test_no_jwt_shaped_strings_in_evidence(self):
        findings = self._all_m81c_findings()
        for f in findings:
            for key, val in f.evidence.items():
                if isinstance(val, str):
                    assert not re.match(r"eyJ[A-Za-z0-9_-]{10,}", val), (
                        f"JWT-shaped string in evidence of {f.rule_key}.{key}"
                    )

    def test_no_sendgrid_secret_shape_in_evidence(self):
        findings = self._all_m81c_findings()
        sg_pattern = re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
        for f in findings:
            for key, val in f.evidence.items():
                if isinstance(val, str):
                    assert not sg_pattern.search(val), (
                        f"SendGrid secret shape in evidence of {f.rule_key}.{key}"
                    )

    def test_all_m81c_rules_produce_at_least_one_finding(self):
        findings = self._all_m81c_findings()
        triggered = _finding_keys(findings)
        missing = M81C_RULE_KEYS - triggered
        assert not missing, f"No finding produced for: {missing}"

    def test_evidence_descriptions_do_not_contain_forbidden_phrases(self):
        findings = self._all_m81c_findings()
        for f in findings:
            combined = f"{f.title} {f.description}".lower()
            for phrase in FORBIDDEN_PHRASES:
                assert phrase not in combined, (
                    f"Forbidden phrase '{phrase}' in finding {f.rule_key}"
                )


# ── Section J: Capability matrix and expansion framework ──────────────────────


class TestCapabilityMatrixAndExpansionFramework:
    def test_capability_matrix_auth0_security_rules_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.security.security_rules is True
        assert cap.drift.drift_risk_classification is True

    def test_capability_matrix_auth0_activity_false(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.security.activity_ingestion is False
        assert cap.security.activity_signals is False
        assert cap.security.risk_activity_correlations is False
        assert cap.security.demo_seed_clear is False

    def test_capability_matrix_auth0_maturity_partial(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.maturity == "partial"

    def test_capability_matrix_auth0_still_partial(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES, PROVIDER_CAPABILITIES_PARTIAL,
        )
        canonical = {p.provider for p in PROVIDER_CAPABILITIES}
        partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert "auth0" not in canonical
        assert "auth0" in partial

    def test_capability_matrix_notes_mention_m81c(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        notes = cap.notes or ""
        assert "M81C" in notes

    def test_expansion_framework_points_to_m81d(self):
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M81D" in planned
        assert "M81C" not in planned


# ── Section K: Forbidden wording in auth0 security rules module ───────────────


class TestForbiddenWording:
    def test_no_forbidden_phrases_in_auth0_rules_module(self):
        from app.services.security_rules import auth0 as auth0_module
        source = inspect.getsource(auth0_module)
        source_lower = source.lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in source_lower, (
                f"Forbidden phrase '{phrase}' found in auth0 security rules module"
            )

    def test_no_forbidden_phrases_in_auth0_connector(self):
        from app.connectors import auth0 as connector_module
        source = inspect.getsource(connector_module)
        source_lower = source.lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in source_lower, (
                f"Forbidden phrase '{phrase}' found in auth0 connector module"
            )


# ── Section L: No secret-shaped strings in backend/app and frontend/src ───────


class TestNoSecretShapes:
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
        assert not violations, f"Secret-shaped strings found:\n" + "\n".join(violations)

    def test_no_secret_shapes_in_frontend_src(self):
        frontend_src = Path(__file__).parent.parent.parent / "frontend" / "src"
        if not frontend_src.exists():
            pytest.skip("frontend/src not found")
        violations = self._scan_dir(frontend_src)
        assert not violations, f"Secret-shaped strings found:\n" + "\n".join(violations)
