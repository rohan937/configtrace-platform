"""M81B — Auth0 core security foundation tests.

Verifies the 22 Auth0 configuration-risk rules implemented in M81B, their
registration across the rule registry / confidence / pack / coverage tables,
the frontend rule catalog parity, the capability matrix update, and the
expansion-framework pointer advance.

Privacy guarantees verified by these tests
------------------------------------------
- Rule evidence never contains client secrets, management tokens, access
  tokens, refresh tokens, ID tokens, JWTs, JWKS, private keys, signing keys,
  authorization headers, raw callback/logout/origin URLs, audience URIs,
  custom domain name strings, rule/action script content, action secret
  names or values, connection credentials, social provider secrets, SAML
  certificates, LDAP credentials, user emails/names/IDs, login history,
  IP addresses, session data, MFA enrollment data, MFA recovery codes,
  customer data, or PII.

Sections
--------
  A. Rule keys / registration parity (registry, confidence, pack, coverage,
     frontend catalog)
  B. Tenant settings rule evaluators
  C. Application rule evaluators
  D. Connection rule evaluators
  E. Resource server rule evaluators
  F. Rule (auth pipeline) evaluators
  G. Action evaluators
  H. MFA factor evaluators
  I. Custom domain evaluators
  J. Privacy / evidence-field scan
  K. Capability matrix and provider expansion framework
  L. Forbidden wording in Auth0 security rules module
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path
from typing import Any

import pytest

from app.connectors.auth0_schema import (
    AUTH0_ACTION,
    AUTH0_APPLICATION,
    AUTH0_CONNECTION,
    AUTH0_CUSTOM_DOMAIN,
    AUTH0_MFA_FACTOR,
    AUTH0_RESOURCE_SERVER,
    AUTH0_RULE,
    AUTH0_TENANT_SETTINGS,
)
from app.services.security_rules.auth0 import AUTH0_RULE_KEYS, evaluate

# ── Expected Auth0 rule keys (M81B baseline) ──────────────────────────────────

EXPECTED_AUTH0_RULE_KEYS = frozenset({
    # Tenant settings
    "auth0_tenant_session_lifetime_extended",
    "auth0_tenant_idle_session_lifetime_extended",
    "auth0_tenant_dynamic_client_registration_enabled",
    # Application
    "auth0_application_no_callbacks",
    "auth0_application_many_callbacks",
    "auth0_application_many_allowed_origins",
    "auth0_application_oidc_non_conformant",
    "auth0_application_weak_jwt_algorithm",
    "auth0_refresh_token_rotation_disabled",
    "auth0_refresh_token_lifetime_extended",
    # Connection
    "auth0_connection_no_enabled_clients",
    "auth0_connection_weak_password_policy",
    # Resource server
    "auth0_resource_server_offline_access_enabled",
    "auth0_resource_server_token_lifetime_extended",
    "auth0_resource_server_rbac_disabled",
    # Rule
    "auth0_rule_disabled",
    "auth0_rule_large_script",
    # Action
    "auth0_action_not_deployed",
    "auth0_action_secrets_present",
    # MFA factor
    "auth0_mfa_factor_disabled",
    # Custom domain
    "auth0_custom_domain_not_ready",
    "auth0_custom_domain_weak_tls_policy",
})

# ── Forbidden claim wording (M75A) ────────────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# ── Sensitive evidence-field names (must NEVER appear in finding evidence) ─────
_SENSITIVE_EVIDENCE_FIELDS = frozenset({
    # Auth0 secrets / tokens
    "client_secret", "management_api_token", "access_token", "refresh_token",
    "id_token", "token", "bearer", "authorization", "signing_secret",
    "private_key", "public_key", "certificate", "cert", "signing_key",
    "jwks", "jwt",
    # Raw URL fields
    "callbacks", "allowed_logout_urls", "allowed_origins", "web_origins",
    "callback_url", "redirect_uri", "initiate_login_uri",
    # Resource server audience URI string
    "identifier", "audience",
    # Custom domain name string
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


# ════════════════════════════════════════════════════════════════════════════
# Section A — Rule keys / registration parity
# ════════════════════════════════════════════════════════════════════════════


def test_auth0_rule_keys_match_expected():
    # M81C adds 15 more rules; check M81B baseline is a subset (not exact equality)
    assert EXPECTED_AUTH0_RULE_KEYS.issubset(set(AUTH0_RULE_KEYS)), (
        f"M81B rule keys missing from AUTH0_RULE_KEYS: "
        f"{EXPECTED_AUTH0_RULE_KEYS - set(AUTH0_RULE_KEYS)}"
    )


def test_auth0_rule_keys_count():
    # M81B baseline is 22; later milestones add more
    assert len(AUTH0_RULE_KEYS) >= 22


def test_auth0_rules_registered_in_registry():
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    missing = EXPECTED_AUTH0_RULE_KEYS - KNOWN_RULE_KEYS
    assert missing == set(), f"Auth0 rules missing from registry: {missing}"


def test_auth0_rules_registered_in_confidence():
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    missing = EXPECTED_AUTH0_RULE_KEYS - set(RULE_CONFIDENCE)
    assert missing == set(), f"Auth0 rules missing from confidence: {missing}"


def test_auth0_rules_registered_in_pack():
    from app.services.security_rule_pack import _RULE_META
    missing = EXPECTED_AUTH0_RULE_KEYS - set(_RULE_META)
    assert missing == set(), f"Auth0 rules missing from rule pack: {missing}"
    # Each rule must be tagged provider="auth0"
    for k in EXPECTED_AUTH0_RULE_KEYS:
        provider, severity, category = _RULE_META[k]
        assert provider == "auth0", (
            f"Rule {k!r} has wrong provider {provider!r}"
        )
        assert severity in ("high", "medium", "low"), (
            f"Rule {k!r} has invalid severity {severity!r}"
        )
        assert category.strip(), f"Rule {k!r} has empty category"


def test_auth0_rules_registered_in_coverage():
    from app.services.security_coverage_service import (
        RULE_RECORD_TYPES, PROVIDERS, PROVIDER_SURFACES,
    )
    assert "auth0" in PROVIDERS
    assert "auth0" in PROVIDER_SURFACES
    assert len(PROVIDER_SURFACES["auth0"]) >= 1
    missing = EXPECTED_AUTH0_RULE_KEYS - set(RULE_RECORD_TYPES)
    assert missing == set(), f"Auth0 rules missing from coverage map: {missing}"


def test_auth0_rules_coverage_record_types_are_auth0():
    """Every Auth0 rule must map to at least one auth0_* record type."""
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    for k in EXPECTED_AUTH0_RULE_KEYS:
        record_types = RULE_RECORD_TYPES[k]
        for rt in record_types:
            assert rt.startswith("auth0_"), (
                f"Auth0 rule {k!r} maps to non-auth0 record type {rt!r}"
            )


# ════════════════════════════════════════════════════════════════════════════
# Section B — Tenant settings rule evaluators
# ════════════════════════════════════════════════════════════════════════════


def _tenant_record(**overrides) -> dict:
    base: dict[str, Any] = {
        "record_type": AUTH0_TENANT_SETTINGS,
        "record_id": "auth0_tenant_settings_main",
        "provider_resource_id": "tenants/settings",
        "friendly_name_present": True,
        "support_email_domain": "example.com",
        "default_directory_present": True,
        "session_lifetime_category": "standard",
        "idle_session_lifetime_category": "short",
        "enabled_locales_count": 1,
        "flag_change_pwd_on_first_login": False,
        "flag_enable_client_connections": True,
        "flag_enable_apis_section": True,
        "flag_enable_pipeline2": True,
        "flag_enable_dynamic_client_registration": False,
        "flag_enable_custom_domain_in_emails": False,
        "flag_universal_login": True,
        "flag_enable_legacy_logs_search_v2": False,
        "flag_no_disclose_enterprise_connections": False,
        "flag_disable_management_api_sms_obfuscation": False,
        "flag_enable_adfs_waad_email_verification": False,
        "flag_revoke_refresh_token_grant": False,
    }
    base.update(overrides)
    return base


def test_tenant_healthy_record_has_no_findings():
    keys = {f.rule_key for f in evaluate(_tenant_record())}
    assert keys == set(), f"healthy tenant fired unexpected rules: {keys}"


def test_tenant_session_lifetime_extended_fires():
    keys = {f.rule_key for f in evaluate(_tenant_record(session_lifetime_category="extended"))}
    assert "auth0_tenant_session_lifetime_extended" in keys


def test_tenant_session_lifetime_standard_does_not_fire():
    keys = {f.rule_key for f in evaluate(_tenant_record(session_lifetime_category="standard"))}
    assert "auth0_tenant_session_lifetime_extended" not in keys


def test_tenant_idle_session_lifetime_extended_fires():
    keys = {f.rule_key for f in evaluate(_tenant_record(idle_session_lifetime_category="extended"))}
    assert "auth0_tenant_idle_session_lifetime_extended" in keys


def test_tenant_dynamic_client_registration_fires():
    keys = {f.rule_key for f in evaluate(
        _tenant_record(flag_enable_dynamic_client_registration=True)
    )}
    assert "auth0_tenant_dynamic_client_registration_enabled" in keys


def test_tenant_dynamic_client_registration_disabled_does_not_fire():
    keys = {f.rule_key for f in evaluate(
        _tenant_record(flag_enable_dynamic_client_registration=False)
    )}
    assert "auth0_tenant_dynamic_client_registration_enabled" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Section C — Application rule evaluators
# ════════════════════════════════════════════════════════════════════════════


def _app_record(**overrides) -> dict:
    base: dict[str, Any] = {
        "record_type": AUTH0_APPLICATION,
        "record_id": "AUTH0_TEST_CLIENT_ID",
        "provider_resource_id": "clients/AUTH0_TEST_CLIENT_ID",
        "client_id": "AUTH0_TEST_CLIENT_ID",
        "name": "Test App",
        "app_type": "spa",
        "is_first_party": True,
        "grant_types_summary": "authorization_code,refresh_token",
        "callbacks_count": 1,
        "allowed_logout_urls_count": 1,
        "allowed_origins_count": 1,
        "web_origins_count": 1,
        "jwt_alg": "RS256",
        "oidc_conformant": True,
        "token_endpoint_auth_method": "none",
        "refresh_token_rotation_enabled": True,
        "refresh_token_lifetime_category": "short",
    }
    base.update(overrides)
    return base


def test_application_healthy_record_has_no_findings():
    # M81B healthy record uses token_endpoint_auth_method="none"; later milestones
    # (M81C) may flag this. Only assert that no M81B baseline rules fire.
    keys = {f.rule_key for f in evaluate(_app_record())}
    m81b_fired = keys & EXPECTED_AUTH0_RULE_KEYS
    assert m81b_fired == set(), f"healthy app fired unexpected M81B rules: {m81b_fired}"


def test_application_no_callbacks_fires_for_spa():
    keys = {f.rule_key for f in evaluate(_app_record(app_type="spa", callbacks_count=0))}
    assert "auth0_application_no_callbacks" in keys


def test_application_no_callbacks_fires_for_regular_web():
    keys = {f.rule_key for f in evaluate(_app_record(app_type="regular_web", callbacks_count=0))}
    assert "auth0_application_no_callbacks" in keys


def test_application_no_callbacks_skips_m2m_and_native():
    """M2M/CLI/native apps without callbacks must not fire — they don't need them."""
    for app_type in ("non_interactive", "native"):
        keys = {f.rule_key for f in evaluate(_app_record(app_type=app_type, callbacks_count=0))}
        assert "auth0_application_no_callbacks" not in keys, (
            f"no_callbacks rule incorrectly fired for app_type={app_type!r}"
        )


def test_application_many_callbacks_fires():
    keys = {f.rule_key for f in evaluate(_app_record(callbacks_count=15))}
    assert "auth0_application_many_callbacks" in keys


def test_application_many_callbacks_does_not_fire_at_threshold():
    keys = {f.rule_key for f in evaluate(_app_record(callbacks_count=10))}
    assert "auth0_application_many_callbacks" not in keys


def test_application_many_origins_fires():
    keys = {f.rule_key for f in evaluate(_app_record(
        allowed_origins_count=8, web_origins_count=8,
    ))}
    assert "auth0_application_many_allowed_origins" in keys


def test_application_many_origins_does_not_fire_at_threshold():
    keys = {f.rule_key for f in evaluate(_app_record(
        allowed_origins_count=5, web_origins_count=5,
    ))}
    assert "auth0_application_many_allowed_origins" not in keys


def test_application_oidc_non_conformant_fires():
    keys = {f.rule_key for f in evaluate(_app_record(oidc_conformant=False))}
    assert "auth0_application_oidc_non_conformant" in keys


def test_application_oidc_conformant_does_not_fire():
    keys = {f.rule_key for f in evaluate(_app_record(oidc_conformant=True))}
    assert "auth0_application_oidc_non_conformant" not in keys


def test_application_weak_jwt_hs256_fires():
    keys = {f.rule_key for f in evaluate(_app_record(jwt_alg="HS256"))}
    assert "auth0_application_weak_jwt_algorithm" in keys


def test_application_weak_jwt_none_fires():
    keys = {f.rule_key for f in evaluate(_app_record(jwt_alg="none"))}
    assert "auth0_application_weak_jwt_algorithm" in keys


def test_application_rs256_does_not_fire_weak_jwt():
    keys = {f.rule_key for f in evaluate(_app_record(jwt_alg="RS256"))}
    assert "auth0_application_weak_jwt_algorithm" not in keys


def test_application_refresh_token_rotation_disabled_fires_with_refresh_grant():
    keys = {f.rule_key for f in evaluate(_app_record(
        grant_types_summary="authorization_code,refresh_token",
        refresh_token_rotation_enabled=False,
    ))}
    assert "auth0_refresh_token_rotation_disabled" in keys


def test_application_refresh_token_rotation_skipped_without_refresh_grant():
    """M2M/client_credentials apps don't issue refresh tokens — rule must skip."""
    keys = {f.rule_key for f in evaluate(_app_record(
        grant_types_summary="client_credentials",
        refresh_token_rotation_enabled=False,
    ))}
    assert "auth0_refresh_token_rotation_disabled" not in keys


def test_application_refresh_token_lifetime_extended_fires():
    keys = {f.rule_key for f in evaluate(_app_record(
        refresh_token_lifetime_category="extended",
    ))}
    assert "auth0_refresh_token_lifetime_extended" in keys


def test_application_refresh_token_lifetime_short_does_not_fire():
    keys = {f.rule_key for f in evaluate(_app_record(
        refresh_token_lifetime_category="short",
    ))}
    assert "auth0_refresh_token_lifetime_extended" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Section D — Connection rule evaluators
# ════════════════════════════════════════════════════════════════════════════


def _connection_record(**overrides) -> dict:
    base: dict[str, Any] = {
        "record_type": AUTH0_CONNECTION,
        "record_id": "AUTH0_TEST_CONNECTION_ID",
        "provider_resource_id": "connections/AUTH0_TEST_CONNECTION_ID",
        "connection_id": "AUTH0_TEST_CONNECTION_ID",
        "name": "Username-Password",
        "strategy": "auth0",
        "enabled_clients_count": 3,
        "is_domain_connection": False,
        "password_policy_category": "good",
        "mfa_enabled": True,
    }
    base.update(overrides)
    return base


def test_connection_healthy_record_has_no_findings():
    keys = {f.rule_key for f in evaluate(_connection_record())}
    assert keys == set(), f"healthy connection fired unexpected rules: {keys}"


def test_connection_no_enabled_clients_fires():
    keys = {f.rule_key for f in evaluate(_connection_record(enabled_clients_count=0))}
    assert "auth0_connection_no_enabled_clients" in keys


def test_connection_weak_password_policy_fires_low():
    keys = {f.rule_key for f in evaluate(_connection_record(password_policy_category="low"))}
    assert "auth0_connection_weak_password_policy" in keys


def test_connection_weak_password_policy_fires_fair():
    keys = {f.rule_key for f in evaluate(_connection_record(password_policy_category="fair"))}
    assert "auth0_connection_weak_password_policy" in keys


def test_connection_weak_password_policy_fires_none():
    keys = {f.rule_key for f in evaluate(_connection_record(password_policy_category="none"))}
    assert "auth0_connection_weak_password_policy" in keys


def test_connection_good_password_policy_does_not_fire():
    keys = {f.rule_key for f in evaluate(_connection_record(password_policy_category="good"))}
    assert "auth0_connection_weak_password_policy" not in keys


def test_connection_excellent_password_policy_does_not_fire():
    keys = {f.rule_key for f in evaluate(_connection_record(password_policy_category="excellent"))}
    assert "auth0_connection_weak_password_policy" not in keys


def test_connection_social_strategy_skipped_for_password_policy():
    """google-oauth2 connection has no password policy — rule must skip even if missing."""
    keys = {f.rule_key for f in evaluate(_connection_record(
        strategy="google-oauth2",
        password_policy_category=None,
    ))}
    assert "auth0_connection_weak_password_policy" not in keys


# ── auth0_connection_mfa_disabled (classification-QA pass) ───────────────────


def test_connection_mfa_disabled_fires():
    keys = {f.rule_key for f in evaluate(_connection_record(mfa_enabled=False))}
    assert "auth0_connection_mfa_disabled" in keys


def test_connection_mfa_enabled_does_not_fire():
    keys = {f.rule_key for f in evaluate(_connection_record(mfa_enabled=True))}
    assert "auth0_connection_mfa_disabled" not in keys


def test_connection_mfa_unknown_does_not_fire():
    """mfa_enabled=None (unknown/not-applicable) must never fire — only an
    explicit False is a finding-worthy signal."""
    keys = {f.rule_key for f in evaluate(_connection_record(mfa_enabled=None))}
    assert "auth0_connection_mfa_disabled" not in keys


def test_connection_mfa_social_strategy_skipped():
    """Social/enterprise connections carry mfa_enabled=None from the connector
    and must never fire this database-connection-only rule."""
    keys = {f.rule_key for f in evaluate(_connection_record(
        strategy="google-oauth2",
        mfa_enabled=None,
    ))}
    assert "auth0_connection_mfa_disabled" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Section E — Resource server rule evaluators
# ════════════════════════════════════════════════════════════════════════════


def _rs_record(**overrides) -> dict:
    base: dict[str, Any] = {
        "record_type": AUTH0_RESOURCE_SERVER,
        "record_id": "AUTH0_TEST_RS_ID",
        "provider_resource_id": "resource-servers/AUTH0_TEST_RS_ID",
        "resource_server_id": "AUTH0_TEST_RS_ID",
        "name": "Test API",
        "identifier_present": True,
        "signing_alg": "RS256",
        "token_lifetime_category": "standard",
        "allow_offline_access": False,
        "skip_consent_for_verifiable_first_party_clients": True,
        "rbac_enabled": True,
        "scopes_count": 4,
    }
    base.update(overrides)
    return base


def test_resource_server_healthy_record_has_no_findings():
    keys = {f.rule_key for f in evaluate(_rs_record())}
    assert keys == set(), f"healthy resource server fired unexpected rules: {keys}"


def test_resource_server_offline_access_fires():
    keys = {f.rule_key for f in evaluate(_rs_record(allow_offline_access=True))}
    assert "auth0_resource_server_offline_access_enabled" in keys


def test_resource_server_offline_access_disabled_does_not_fire():
    keys = {f.rule_key for f in evaluate(_rs_record(allow_offline_access=False))}
    assert "auth0_resource_server_offline_access_enabled" not in keys


def test_resource_server_token_lifetime_extended_fires():
    keys = {f.rule_key for f in evaluate(_rs_record(token_lifetime_category="extended"))}
    assert "auth0_resource_server_token_lifetime_extended" in keys


def test_resource_server_token_lifetime_standard_does_not_fire():
    keys = {f.rule_key for f in evaluate(_rs_record(token_lifetime_category="standard"))}
    assert "auth0_resource_server_token_lifetime_extended" not in keys


def test_resource_server_rbac_disabled_fires():
    keys = {f.rule_key for f in evaluate(_rs_record(rbac_enabled=False))}
    assert "auth0_resource_server_rbac_disabled" in keys


def test_resource_server_rbac_enabled_does_not_fire():
    keys = {f.rule_key for f in evaluate(_rs_record(rbac_enabled=True))}
    assert "auth0_resource_server_rbac_disabled" not in keys


# ── auth0_resource_server_weak_signing_algorithm (classification-QA pass) ────


def test_resource_server_weak_signing_algorithm_fires_hs256():
    keys = {f.rule_key for f in evaluate(_rs_record(signing_alg="HS256"))}
    assert "auth0_resource_server_weak_signing_algorithm" in keys


def test_resource_server_weak_signing_algorithm_fires_none():
    keys = {f.rule_key for f in evaluate(_rs_record(signing_alg="none"))}
    assert "auth0_resource_server_weak_signing_algorithm" in keys


def test_resource_server_rs256_does_not_fire_weak_signing():
    keys = {f.rule_key for f in evaluate(_rs_record(signing_alg="RS256"))}
    assert "auth0_resource_server_weak_signing_algorithm" not in keys


def test_resource_server_signing_alg_missing_does_not_fire():
    """An empty/missing signing_alg must never fire — only an explicit weak
    algorithm value is a finding-worthy signal."""
    keys = {f.rule_key for f in evaluate(_rs_record(signing_alg=""))}
    assert "auth0_resource_server_weak_signing_algorithm" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Section F — Rule (auth pipeline) evaluators
# ════════════════════════════════════════════════════════════════════════════


def _rule_record(**overrides) -> dict:
    base: dict[str, Any] = {
        "record_type": AUTH0_RULE,
        "record_id": "AUTH0_TEST_RULE_ID",
        "provider_resource_id": "rules/AUTH0_TEST_RULE_ID",
        "rule_id": "AUTH0_TEST_RULE_ID",
        "name": "Add roles",
        "enabled": True,
        "order": 1,
        "script_present": True,
        "script_length_category": "short",
        "stage": "login_success",
    }
    base.update(overrides)
    return base


def test_rule_healthy_record_has_no_findings():
    keys = {f.rule_key for f in evaluate(_rule_record())}
    assert keys == set(), f"healthy rule fired unexpected rules: {keys}"


def test_rule_disabled_with_script_fires():
    keys = {f.rule_key for f in evaluate(_rule_record(enabled=False, script_present=True))}
    assert "auth0_rule_disabled" in keys


def test_rule_disabled_without_script_does_not_fire():
    """Disabled rules without a script are likely just empty placeholders."""
    keys = {f.rule_key for f in evaluate(_rule_record(
        enabled=False, script_present=False, script_length_category="absent",
    ))}
    assert "auth0_rule_disabled" not in keys


def test_rule_enabled_does_not_fire_disabled_rule():
    keys = {f.rule_key for f in evaluate(_rule_record(enabled=True))}
    assert "auth0_rule_disabled" not in keys


def test_rule_large_script_fires():
    keys = {f.rule_key for f in evaluate(_rule_record(script_length_category="long"))}
    assert "auth0_rule_large_script" in keys


def test_rule_medium_script_does_not_fire():
    keys = {f.rule_key for f in evaluate(_rule_record(script_length_category="medium"))}
    assert "auth0_rule_large_script" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Section G — Action evaluators
# ════════════════════════════════════════════════════════════════════════════


def _action_record(**overrides) -> dict:
    base: dict[str, Any] = {
        "record_type": AUTH0_ACTION,
        "record_id": "AUTH0_TEST_ACTION_ID",
        "provider_resource_id": "actions/actions/AUTH0_TEST_ACTION_ID",
        "action_id": "AUTH0_TEST_ACTION_ID",
        "name": "Add roles",
        "status": "built",
        "runtime": "node18-actions",
        "trigger_id": "post-login",
        "code_present": True,
        "code_length_category": "short",
        "deployed_version_present": True,
        "dependencies_count": 0,
        "secrets_count": 0,
    }
    base.update(overrides)
    return base


def test_action_healthy_record_has_no_findings():
    keys = {f.rule_key for f in evaluate(_action_record())}
    assert keys == set(), f"healthy action fired unexpected rules: {keys}"


def test_action_not_deployed_fires():
    keys = {f.rule_key for f in evaluate(_action_record(deployed_version_present=False))}
    assert "auth0_action_not_deployed" in keys


def test_action_deployed_does_not_fire():
    keys = {f.rule_key for f in evaluate(_action_record(deployed_version_present=True))}
    assert "auth0_action_not_deployed" not in keys


def test_action_secrets_present_fires():
    keys = {f.rule_key for f in evaluate(_action_record(secrets_count=3))}
    assert "auth0_action_secrets_present" in keys


def test_action_no_secrets_does_not_fire():
    keys = {f.rule_key for f in evaluate(_action_record(secrets_count=0))}
    assert "auth0_action_secrets_present" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Section H — MFA factor evaluators
# ════════════════════════════════════════════════════════════════════════════


def _mfa_record(**overrides) -> dict:
    base: dict[str, Any] = {
        "record_type": AUTH0_MFA_FACTOR,
        "record_id": "auth0_mfa_factor_otp",
        "provider_resource_id": "guardian/factors/otp",
        "factor_name": "otp",
        "enabled": True,
        "trial_expired": None,
        "provider_category": "totp",
    }
    base.update(overrides)
    return base


def test_mfa_strong_factor_disabled_fires():
    keys = {f.rule_key for f in evaluate(_mfa_record(factor_name="otp", enabled=False))}
    assert "auth0_mfa_factor_disabled" in keys


def test_mfa_webauthn_disabled_fires():
    keys = {f.rule_key for f in evaluate(_mfa_record(
        factor_name="webauthn-roaming", enabled=False, provider_category="webauthn",
    ))}
    assert "auth0_mfa_factor_disabled" in keys


def test_mfa_push_disabled_fires():
    keys = {f.rule_key for f in evaluate(_mfa_record(
        factor_name="push-notification", enabled=False, provider_category="push",
    ))}
    assert "auth0_mfa_factor_disabled" in keys


def test_mfa_enabled_strong_factor_does_not_fire():
    keys = {f.rule_key for f in evaluate(_mfa_record(factor_name="otp", enabled=True))}
    assert "auth0_mfa_factor_disabled" not in keys


def test_mfa_weak_factor_disabled_does_not_fire():
    """SMS / email are not in the strong-factor list — disabling them is not a finding."""
    for factor in ("sms", "email"):
        keys = {f.rule_key for f in evaluate(_mfa_record(
            factor_name=factor, enabled=False, provider_category=factor,
        ))}
        assert "auth0_mfa_factor_disabled" not in keys, (
            f"mfa_factor_disabled unexpectedly fired for non-strong factor {factor!r}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section I — Custom domain evaluators
# ════════════════════════════════════════════════════════════════════════════


def _custom_domain_record(**overrides) -> dict:
    base: dict[str, Any] = {
        "record_type": AUTH0_CUSTOM_DOMAIN,
        "record_id": "AUTH0_TEST_DOMAIN_ID",
        "provider_resource_id": "custom-domains/AUTH0_TEST_DOMAIN_ID",
        "custom_domain_id": "AUTH0_TEST_DOMAIN_ID",
        "domain_present": True,
        "status": "ready",
        "type": "auth0_managed_certs",
        "primary": True,
        "verification_method_category": "txt",
        "tls_policy_category": "recommended",
    }
    base.update(overrides)
    return base


def test_custom_domain_ready_has_no_findings():
    keys = {f.rule_key for f in evaluate(_custom_domain_record())}
    assert keys == set(), f"healthy custom domain fired unexpected rules: {keys}"


def test_custom_domain_pending_verification_fires():
    keys = {f.rule_key for f in evaluate(_custom_domain_record(status="pending_verification"))}
    assert "auth0_custom_domain_not_ready" in keys


def test_custom_domain_provisioning_fires():
    keys = {f.rule_key for f in evaluate(_custom_domain_record(status="provisioning"))}
    assert "auth0_custom_domain_not_ready" in keys


def test_custom_domain_disabled_fires():
    keys = {f.rule_key for f in evaluate(_custom_domain_record(status="disabled"))}
    assert "auth0_custom_domain_not_ready" in keys


def test_custom_domain_ready_does_not_fire():
    keys = {f.rule_key for f in evaluate(_custom_domain_record(status="ready"))}
    assert "auth0_custom_domain_not_ready" not in keys


def test_custom_domain_weak_tls_fires():
    keys = {f.rule_key for f in evaluate(_custom_domain_record(tls_policy_category="compatible"))}
    assert "auth0_custom_domain_weak_tls_policy" in keys


def test_custom_domain_recommended_tls_does_not_fire():
    keys = {f.rule_key for f in evaluate(_custom_domain_record(tls_policy_category="recommended"))}
    assert "auth0_custom_domain_weak_tls_policy" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Section J — Privacy / evidence-field scan
# ════════════════════════════════════════════════════════════════════════════


def _all_test_records() -> list[dict]:
    """Build one polluted record per type to exercise every evaluator path."""
    return [
        # Tenant — every rule trigger active
        _tenant_record(
            session_lifetime_category="extended",
            idle_session_lifetime_category="extended",
            flag_enable_dynamic_client_registration=True,
        ),
        # Application — every applicable rule trigger active
        _app_record(
            app_type="spa",
            callbacks_count=15,
            allowed_origins_count=8,
            web_origins_count=8,
            oidc_conformant=False,
            jwt_alg="HS256",
            grant_types_summary="authorization_code,refresh_token",
            refresh_token_rotation_enabled=False,
            refresh_token_lifetime_category="extended",
        ),
        # App with zero callbacks — separate trigger
        _app_record(app_type="regular_web", callbacks_count=0),
        # Connection — both triggers
        _connection_record(enabled_clients_count=0, password_policy_category="low"),
        # Resource server — every trigger
        _rs_record(
            allow_offline_access=True,
            token_lifetime_category="extended",
            rbac_enabled=False,
        ),
        # Rule — both triggers
        _rule_record(enabled=False, script_present=True, script_length_category="long"),
        # Action — both triggers
        _action_record(deployed_version_present=False, secrets_count=3),
        # MFA factor — strong factor disabled
        _mfa_record(factor_name="otp", enabled=False),
        # Custom domain — both triggers
        _custom_domain_record(status="pending_verification", tls_policy_category="compatible"),
    ]


def test_no_finding_evidence_contains_sensitive_field_names():
    """No finding evidence dict may use a sensitive field name as a key."""
    for record in _all_test_records():
        findings = evaluate(record)
        for finding in findings:
            for k in finding.evidence.keys():
                assert k not in _SENSITIVE_EVIDENCE_FIELDS, (
                    f"Rule {finding.rule_key!r} evidence contains sensitive "
                    f"field name {k!r}"
                )


def test_no_finding_blob_contains_jwt_shaped_strings():
    """No finding evidence/title/description may contain JWT-shaped values."""
    for record in _all_test_records():
        for finding in evaluate(record):
            blob = json.dumps({
                "title": finding.title,
                "description": finding.description,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
            }, default=str)
            assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", blob), (
                f"Rule {finding.rule_key!r} contains a JWT-shaped string"
            )
            # No Auth0 AC/SK hex-shape either (Twilio shapes; defense in depth)
            assert not re.search(r"AC[0-9a-fA-F]{32}", blob)
            assert not re.search(r"SK[0-9a-fA-F]{32}", blob)
            # SendGrid API key shape
            assert not re.search(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", blob)


def test_no_finding_contains_forbidden_claim_wording():
    """No finding may contain a forbidden claim phrase outside negation."""
    for record in _all_test_records():
        for finding in evaluate(record):
            blob = (
                finding.title + " " + finding.description + " "
                + json.dumps(finding.remediation, default=str)
            ).lower()
            # Strip any sentence/clause that is an explicit negation of a phrase.
            # Heuristic: replace "does not confirm" + sentence-end with "" for the scan.
            for phrase in FORBIDDEN_PHRASES:
                assert phrase not in blob, (
                    f"Rule {finding.rule_key!r} contains forbidden phrase {phrase!r}"
                )


def test_findings_have_metadata_only_evidence_values():
    """Evidence values must be flat scalars (bool/int/str/None) — no nested dicts/lists
    that could smuggle in raw payloads."""
    for record in _all_test_records():
        for finding in evaluate(record):
            for k, v in finding.evidence.items():
                assert v is None or isinstance(v, (bool, int, float, str)), (
                    f"Rule {finding.rule_key!r} evidence field {k!r} has "
                    f"non-scalar value type {type(v).__name__}"
                )


def test_evaluator_returns_empty_for_unknown_record_type():
    assert evaluate({"record_type": "auth0_unknown_thing"}) == []
    assert evaluate({}) == []
    assert evaluate({"record_type": ""}) == []
    # Defensive: non-dict input
    assert evaluate(None) == []  # type: ignore[arg-type]
    assert evaluate("not a dict") == []  # type: ignore[arg-type]


def test_all_findings_use_provider_auth0():
    """Every produced FindingCandidate must carry provider='auth0'."""
    for record in _all_test_records():
        for finding in evaluate(record):
            assert finding.provider == "auth0", (
                f"Rule {finding.rule_key!r} has wrong provider {finding.provider!r}"
            )


def test_all_findings_have_finding_key_with_rule_key_prefix():
    for record in _all_test_records():
        for finding in evaluate(record):
            assert finding.finding_key.startswith(finding.rule_key), (
                f"finding_key {finding.finding_key!r} does not start with "
                f"rule_key {finding.rule_key!r}"
            )


def test_all_findings_have_severity_and_title():
    for record in _all_test_records():
        for finding in evaluate(record):
            assert finding.severity in ("critical", "high", "medium", "low", "info"), (
                f"Rule {finding.rule_key!r} has invalid severity {finding.severity!r}"
            )
            assert finding.title.strip(), f"Rule {finding.rule_key!r} has empty title"
            assert finding.description.strip(), (
                f"Rule {finding.rule_key!r} has empty description"
            )


# ════════════════════════════════════════════════════════════════════════════
# Section K — Capability matrix and provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_auth0_security_rules_now_true():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("auth0")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.drift.drift_risk_classification is True
    # activity_ingestion M81D, signals M81E, correlations M81F, demo M81G — all complete
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.maturity == "partial"


def test_capability_matrix_auth0_notes_mention_m81b():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("auth0")
    notes = cap.notes or ""
    assert "M81B" in notes, "Auth0 capability notes must mention M81B"
    assert "22" in notes or "twenty-two" in notes.lower() or "rules" in notes.lower()


def test_capability_matrix_auth0_still_partial():
    from app.services.provider_capability_matrix_service import (
        PROVIDER_CAPABILITIES, PROVIDER_CAPABILITIES_PARTIAL,
    )
    canonical = {p.provider for p in PROVIDER_CAPABILITIES}
    partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
    assert "auth0" not in canonical
    assert "auth0" in partial


def test_expansion_framework_planned_next_stage_is_m81c():
    # After M81C completes, the pointer advances to M81D — either M81C or beyond is fine
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M81B" not in stage, (
        f"M81B is done; pointer must advance past it (got: {stage!r})"
    )
    assert any(tag in stage for tag in ("M81C", "M81D", "M81E", "M81F", "M81G", "M81H", "M81I", "M82", "M83", "M84", "M85", "M86", "M87", "M88", "M89", "Kubernetes")), (
        f"planned_next_stage should point to M81C or beyond after M81B; got: {stage!r}"
    )


def test_expansion_framework_auth0_still_not_in_recommended():
    """Auth0 launched M81A — must remain out of the recommended queue."""
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    providers = [r["provider"] for r in fw["recommended_next_providers"]]
    assert "auth0" not in providers


# ════════════════════════════════════════════════════════════════════════════
# Section L — Forbidden wording in Auth0 security rules module
# ════════════════════════════════════════════════════════════════════════════


def _strip_negation_contexts(src: str) -> str:
    out = []
    for line in src.splitlines():
        low = line.lower()
        if any(
            tok in low
            for tok in (
                "does not confirm", "never assert", "never claim",
                "do not claim", "forbidden", "not confirm",
                "claim discipline", "review-safe", "without claiming",
                "does not assert",
            )
        ):
            continue
        out.append(line)
    return "\n".join(out)


def test_auth0_security_rules_module_no_forbidden_wording():
    from app.services.security_rules import auth0 as auth0_rules
    src = inspect.getsource(auth0_rules)
    stripped = _strip_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"security_rules.auth0 contains forbidden phrase {phrase!r}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section M — Frontend rule catalog consistency (skip if frontend tree absent)
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


def test_fe_rule_catalog_includes_all_22_auth0_rules():
    text = _read_fe("lib/securityRuleCatalog.ts")
    entries = frozenset(re.findall(r'key:\s*"(auth0_[a-z0-9_]+)"', text))
    missing = EXPECTED_AUTH0_RULE_KEYS - entries
    assert missing == set(), (
        f"frontend securityRuleCatalog missing Auth0 rule keys: {missing}"
    )


def test_fe_rule_catalog_auth0_rules_have_descriptions():
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(auth0_[a-z0-9_]+)".*?description:\s*"([^"]{20,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_AUTH0_RULE_KEYS - found_keys
    assert missing == set(), (
        f"Auth0 rules missing description in catalog: {missing}"
    )


def test_fe_rule_catalog_auth0_rules_have_remediation():
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(auth0_[a-z0-9_]+)".*?remediation:\s*"([^"]{20,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_AUTH0_RULE_KEYS - found_keys
    assert missing == set(), (
        f"Auth0 rules missing remediation in catalog: {missing}"
    )


def test_fe_rule_catalog_auth0_rules_have_false_positive_guard():
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(auth0_[a-z0-9_]+)".*?falsePositiveGuard:\s*"([^"]{10,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_AUTH0_RULE_KEYS - found_keys
    assert missing == set(), (
        f"Auth0 rules missing falsePositiveGuard in catalog: {missing}"
    )


def test_fe_rule_catalog_auth0_section_no_forbidden_wording():
    text = _read_fe("lib/securityRuleCatalog.ts")
    start = text.find('"auth0_tenant_session_lifetime_extended"')
    assert start != -1
    auth0_section = text[start:]
    end = auth0_section.find("// ── Deferred")
    if end > 0:
        auth0_section = auth0_section[:end]
    low = auth0_section.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"securityRuleCatalog Auth0 section contains forbidden phrase {phrase!r}"
        )


def test_fe_rule_catalog_provider_coverage_includes_auth0():
    text = _read_fe("lib/securityRuleCatalog.ts")
    assert 'provider: "auth0"' in text
    for surface in ("Tenant settings", "Applications", "Connections",
                    "APIs", "Rules", "Actions", "MFA", "Custom domains"):
        assert surface in text, (
            f"PROVIDER_COVERAGE auth0 entry missing surface {surface!r}"
        )
