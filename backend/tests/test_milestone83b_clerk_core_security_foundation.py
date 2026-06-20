"""M83B — Clerk core security foundation tests.

Verifies all 21 Clerk configuration-risk rules, registry/confidence/pack/
coverage wiring, capability matrix update, expansion framework pointer,
and frontend catalog.

Privacy guarantees verified by these tests
------------------------------------------
- Evidence never contains Clerk secret key values, publishable key values,
  session tokens, JWTs, OAuth tokens, bearer tokens, webhook secrets
- Evidence never contains raw webhook URLs, raw redirect URLs, raw callback URLs
- Evidence never contains raw domain names, raw JWT template bodies, raw claims
- Evidence never contains audience values, issuer values, user emails
- Evidence never contains user IDs, phone numbers, names, organization member
  identities, session history, login history, password data
- Evidence never contains MFA secrets, backup codes, IP addresses, user agents

Sections
--------
  A. Rule key taxonomy
  B. Rule trigger tests (positive cases — all 21 rules)
  C. Rule non-trigger tests (negative / healthy records)
  D. Evidence privacy scan (no secrets, PII, URLs in evidence)
  E. Registry / confidence / pack wiring
  F. Coverage service (clerk provider, record types)
  G. Capability matrix + expansion framework
  H. Frontend catalog (clerk entries present)
  I. Forbidden wording scan
  J. Secret-shape grep
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from app.services.security_rules.clerk import (
    CLERK_RULE_KEYS,
    evaluate,
)
from app.connectors.clerk_schema import (
    CLERK_INSTANCE_SETTINGS,
    CLERK_APPLICATION,
    CLERK_DOMAIN,
    CLERK_REDIRECT_URL_CONFIG,
    CLERK_JWT_TEMPLATE,
    CLERK_WEBHOOK_ENDPOINT,
    CLERK_EMAIL_SMS_SETTINGS,
    CLERK_AUTH_STRATEGY,
    CLERK_ORGANIZATION_SETTINGS,
    CLERK_SESSION_POLICY,
)
from app.services.security_rule_registry import KNOWN_RULE_KEYS, is_known_rule_key
from app.services.security_rule_confidence import RULE_CONFIDENCE, confidence_for
from app.services.security_rule_pack import _RULE_META, pack_summary, list_pack_rules
from app.services.security_coverage_service import PROVIDERS, RULE_RECORD_TYPES, PROVIDER_SURFACES
from app.services.security_finding_evaluator import _PROVIDER_RULES, evaluate_record
from app.services.provider_capability_matrix_service import get_matrix as get_capability_matrix
from app.services.provider_expansion_framework import get_framework

# ── Test constants ─────────────────────────────────────────────────────────────

# Safe placeholder values — NOT real credentials.
CLERK_TEST_SECRET_KEY = "CLERK_TEST_SECRET_KEY_PLACEHOLDER"
CLERK_TEST_PUBLISHABLE_KEY = "CLERK_TEST_PUBLISHABLE_KEY_PLACEHOLDER"
CLERK_TEST_INSTANCE_ID = "CLERK_TEST_INSTANCE_ID"
CLERK_TEST_WEBHOOK_ID = "CLERK_TEST_WEBHOOK_ID"
CLERK_TEST_TEMPLATE_ID = "CLERK_TEST_TEMPLATE_ID"

EXPECTED_RULE_KEYS = {
    "clerk_instance_mfa_disabled",
    "clerk_instance_password_without_mfa",
    "clerk_instance_sign_up_enabled",
    "clerk_application_mfa_not_required",
    "clerk_domain_unverified",
    "clerk_domain_ssl_disabled",
    "clerk_redirect_url_non_https",
    "clerk_redirect_url_wildcard_present",
    "clerk_redirect_url_localhost_present",
    "clerk_jwt_template_custom_claims_present",
    "clerk_jwt_template_long_lifetime",
    "clerk_webhook_endpoint_disabled",
    "clerk_webhook_without_signing",
    "clerk_webhook_non_https",
    "clerk_email_sms_custom_sender_present",
    "clerk_auth_strategy_mfa_not_required",
    "clerk_auth_strategy_password_without_mfa",
    "clerk_session_lifetime_extended",
    "clerk_session_inactivity_timeout_extended",
    "clerk_session_single_session_disabled",
    "clerk_session_token_rotation_disabled",
}

# Fields that must NEVER appear as keys in any evidence dict.
# Note: "name" is NOT forbidden here because the Clerk evaluator legitimately
# uses it for truncated config-entity labels (app name, JWT template name) —
# these are safe display labels, not user PII. User-identifying name fields
# are covered by "user_email", "user_id", "member", etc.
_FORBIDDEN_EVIDENCE_FIELDS = frozenset({
    "secret_key", "publishable_key", "api_key", "token", "bearer", "jwt",
    "session_token", "webhook_secret", "url", "webhook_url", "redirect_url",
    "callback_url", "domain_name", "template_body", "claims", "audience",
    "issuer", "email", "user_email", "user_id", "phone", "member",
    "ip_address", "user_agent",
})

# Strings that must NEVER appear in any evidence string value.
_FORBIDDEN_EVIDENCE_STRINGS = [
    "eyJ",
    "pk_live_",
    "sk_live_",
    "clerk.com",
    "https://",
    "http://",
    "localhost",
    "@",
]


# ── Record builder helpers ─────────────────────────────────────────────────────


def _instance_settings(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_instance_settings record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_INSTANCE_SETTINGS,
        "provider": "clerk",
        "record_id": CLERK_TEST_INSTANCE_ID,
        "provider_resource_id": "instance/settings",
        "environment_type": "production",
        "sign_up_enabled": False,
        "sign_in_enabled": True,
        "email_enabled": True,
        "phone_enabled": False,
        "username_enabled": False,
        "password_enabled": True,
        "social_provider_count": 2,
        "mfa_enabled": True,
        "mfa_factor_count": 1,
        "session_lifetime_category": "standard",
        "allowed_redirect_count": 2,
        "domain_count": 1,
        "webhook_count": 1,
        "allowlist_enabled": False,
        "blocklist_enabled": False,
        "sign_in_mode": "public",
    }
    defaults.update(kwargs)
    return defaults


def _application(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_application record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_APPLICATION,
        "provider": "clerk",
        "record_id": "clerk_app_opaque_001",
        "provider_resource_id": "applications/clerk_app_opaque_001",
        "name": "My Application",
        "application_type": "web",
        "enabled": True,
        "oauth_provider_count": 2,
        "redirect_url_count": 3,
        "allowed_origin_count": 2,
        "jwt_template_count": 1,
        "organization_enabled": False,
        "mfa_required": True,
    }
    defaults.update(kwargs)
    return defaults


def _domain(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_domain record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_DOMAIN,
        "provider": "clerk",
        "record_id": "dmn_opaque_001",
        "provider_resource_id": "domains/dmn_opaque_001",
        "domain_present": True,
        "domain_type": "primary",
        "verified": True,
        "primary": True,
        "ssl_enabled": True,
        "dns_status_category": "verified",
        "proxy_enabled": False,
    }
    defaults.update(kwargs)
    return defaults


def _redirect_url(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_redirect_url_config record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_REDIRECT_URL_CONFIG,
        "provider": "clerk",
        "record_id": "ru_opaque_001",
        "provider_resource_id": "redirect_urls/ru_opaque_001",
        "url_present": True,
        "url_scheme_category": "https",
        "wildcard_present": False,
        "localhost_present": False,
        "custom_scheme_present": False,
    }
    defaults.update(kwargs)
    return defaults


def _jwt_template(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_jwt_template record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_JWT_TEMPLATE,
        "provider": "clerk",
        "record_id": CLERK_TEST_TEMPLATE_ID,
        "provider_resource_id": f"jwt_templates/{CLERK_TEST_TEMPLATE_ID}",
        "name": "Standard JWT",
        "enabled": True,
        "claims_count": 0,
        "custom_claims_present": False,
        "audience_present": True,
        "lifetime_category": "standard",
        "algorithm": "RS256",
    }
    defaults.update(kwargs)
    return defaults


def _webhook_endpoint(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_webhook_endpoint record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_WEBHOOK_ENDPOINT,
        "provider": "clerk",
        "record_id": CLERK_TEST_WEBHOOK_ID,
        "provider_resource_id": f"webhooks/{CLERK_TEST_WEBHOOK_ID}",
        "enabled": True,
        "url_present": True,
        "url_scheme_category": "https",
        "event_count": 3,
        "secret_present": True,
        "description_present": True,
    }
    defaults.update(kwargs)
    return defaults


def _email_sms_settings(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_email_sms_settings record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_EMAIL_SMS_SETTINGS,
        "provider": "clerk",
        "record_id": "clerk_email_sms_settings_main",
        "provider_resource_id": "instance/email_sms",
        "email_enabled": True,
        "sms_enabled": False,
        "custom_sender_present": False,
        "template_customization_present": False,
    }
    defaults.update(kwargs)
    return defaults


def _auth_strategy(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_auth_strategy record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_AUTH_STRATEGY,
        "provider": "clerk",
        "record_id": "clerk_auth_strategy_main",
        "provider_resource_id": "instance/auth_strategy",
        "password_enabled": True,
        "oauth_enabled": True,
        "social_provider_count": 2,
        "saml_enabled": False,
        "mfa_enabled": True,
        "mfa_required": True,
        "passkey_enabled": False,
        "magic_link_enabled": False,
        "email_otp_enabled": True,
        "phone_otp_enabled": False,
    }
    defaults.update(kwargs)
    return defaults


def _organization_settings(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_organization_settings record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_ORGANIZATION_SETTINGS,
        "provider": "clerk",
        "record_id": "clerk_organization_settings_main",
        "provider_resource_id": "instance/organization",
        "organizations_enabled": True,
        "max_allowed_memberships_category": "limited",
        "admin_delete_enabled": False,
        "domains_enabled": True,
        "domains_enrollment_mode_category": "manual",
    }
    defaults.update(kwargs)
    return defaults


def _session_policy(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_session_policy record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_SESSION_POLICY,
        "provider": "clerk",
        "record_id": "clerk_session_policy_main",
        "provider_resource_id": "instance/session",
        "session_lifetime_category": "standard",
        "inactivity_timeout_category": "standard",
        "single_session_mode": True,
        "url_based_session_syncing": False,
        "token_rotation_enabled": True,
    }
    defaults.update(kwargs)
    return defaults


def _rule_keys(findings: list) -> set[str]:
    """Extract set of rule_key strings from a list of FindingCandidate objects."""
    return {f.rule_key for f in findings}


# ── Section A: Rule key taxonomy ──────────────────────────────────────────────


class TestRuleKeyTaxonomy:
    def test_clerk_rule_keys_matches_expected(self):
        """CLERK_RULE_KEYS must contain all 21 expected rule keys."""
        assert EXPECTED_RULE_KEYS <= CLERK_RULE_KEYS

    def test_rule_count_is_twenty_one(self):
        # M83B introduced 21 rules; subsequent milestones (M83C+) expand the set.
        assert len(EXPECTED_RULE_KEYS) == 21
        assert len(CLERK_RULE_KEYS) >= 21

    def test_all_rule_keys_start_with_clerk(self):
        for key in CLERK_RULE_KEYS:
            assert key.startswith("clerk_"), f"Rule key {key!r} does not start with 'clerk_'"

    def test_all_rule_keys_are_lowercase(self):
        for key in CLERK_RULE_KEYS:
            assert key == key.lower(), f"Rule key {key!r} is not lowercase"

    def test_all_rule_keys_are_strings(self):
        for key in CLERK_RULE_KEYS:
            assert isinstance(key, str)

    def test_evaluate_unknown_record_type(self):
        assert evaluate({"record_type": "unknown_type"}) == []

    def test_evaluate_non_dict(self):
        assert evaluate("not_a_dict") == []  # type: ignore[arg-type]

    def test_evaluate_empty_dict(self):
        assert evaluate({}) == []

    def test_evaluate_none_returns_empty(self):
        assert evaluate(None) == []  # type: ignore[arg-type]


# ── Section B: Rule trigger tests (positive cases — all 21 rules) ─────────────


class TestInstanceSettingsRulesTrigger:
    def test_clerk_instance_mfa_disabled_fires_when_mfa_enabled_false(self):
        """Fires when mfa_enabled=False."""
        keys = _rule_keys(evaluate(_instance_settings(mfa_enabled=False)))
        assert "clerk_instance_mfa_disabled" in keys

    def test_clerk_instance_password_without_mfa_fires(self):
        """Fires when password_enabled=True and mfa_enabled=False."""
        keys = _rule_keys(evaluate(_instance_settings(
            password_enabled=True,
            mfa_enabled=False,
        )))
        assert "clerk_instance_password_without_mfa" in keys

    def test_clerk_instance_sign_up_enabled_fires_when_sign_up_enabled_true(self):
        """Fires when sign_up_enabled=True."""
        keys = _rule_keys(evaluate(_instance_settings(sign_up_enabled=True)))
        assert "clerk_instance_sign_up_enabled" in keys

    def test_multiple_instance_rules_can_fire_together(self):
        """When both mfa_enabled=False and sign_up_enabled=True, multiple rules fire."""
        keys = _rule_keys(evaluate(_instance_settings(
            mfa_enabled=False,
            password_enabled=True,
            sign_up_enabled=True,
        )))
        assert "clerk_instance_mfa_disabled" in keys
        assert "clerk_instance_password_without_mfa" in keys
        assert "clerk_instance_sign_up_enabled" in keys


class TestApplicationRulesTrigger:
    def test_clerk_application_mfa_not_required_fires_when_false(self):
        """Fires when mfa_required=False (explicitly False, not None)."""
        keys = _rule_keys(evaluate(_application(mfa_required=False)))
        assert "clerk_application_mfa_not_required" in keys

    def test_clerk_application_mfa_not_required_does_not_fire_when_none(self):
        """mfa_required=None (not set) must NOT fire — evaluator checks 'is False'."""
        # Make a record without mfa_required set
        rec = _application()
        del rec["mfa_required"]
        keys = _rule_keys(evaluate(rec))
        assert "clerk_application_mfa_not_required" not in keys


class TestDomainRulesTrigger:
    def test_clerk_domain_unverified_fires_when_verified_false(self):
        """Fires when verified=False."""
        keys = _rule_keys(evaluate(_domain(verified=False)))
        assert "clerk_domain_unverified" in keys

    def test_clerk_domain_ssl_disabled_fires_when_ssl_enabled_false(self):
        """Fires when ssl_enabled=False."""
        keys = _rule_keys(evaluate(_domain(ssl_enabled=False)))
        assert "clerk_domain_ssl_disabled" in keys

    def test_both_domain_rules_can_fire_together(self):
        keys = _rule_keys(evaluate(_domain(verified=False, ssl_enabled=False)))
        assert "clerk_domain_unverified" in keys
        assert "clerk_domain_ssl_disabled" in keys


class TestRedirectUrlRulesTrigger:
    def test_clerk_redirect_url_non_https_fires_when_http(self):
        """Fires when url_present=True and url_scheme_category='http'."""
        keys = _rule_keys(evaluate(_redirect_url(
            url_present=True,
            url_scheme_category="http",
        )))
        assert "clerk_redirect_url_non_https" in keys

    def test_clerk_redirect_url_non_https_fires_for_custom_scheme(self):
        """Also fires for custom schemes (not 'https')."""
        keys = _rule_keys(evaluate(_redirect_url(
            url_present=True,
            url_scheme_category="custom",
        )))
        assert "clerk_redirect_url_non_https" in keys

    def test_clerk_redirect_url_wildcard_present_fires_when_true(self):
        """Fires when wildcard_present=True."""
        keys = _rule_keys(evaluate(_redirect_url(wildcard_present=True)))
        assert "clerk_redirect_url_wildcard_present" in keys

    def test_clerk_redirect_url_localhost_present_fires_when_true(self):
        """Fires when localhost_present=True."""
        keys = _rule_keys(evaluate(_redirect_url(localhost_present=True)))
        assert "clerk_redirect_url_localhost_present" in keys

    def test_all_redirect_url_rules_can_fire_together(self):
        keys = _rule_keys(evaluate(_redirect_url(
            url_present=True,
            url_scheme_category="http",
            wildcard_present=True,
            localhost_present=True,
        )))
        assert "clerk_redirect_url_non_https" in keys
        assert "clerk_redirect_url_wildcard_present" in keys
        assert "clerk_redirect_url_localhost_present" in keys


class TestJwtTemplateRulesTrigger:
    def test_clerk_jwt_template_custom_claims_present_fires_when_true(self):
        """Fires when custom_claims_present=True."""
        keys = _rule_keys(evaluate(_jwt_template(custom_claims_present=True)))
        assert "clerk_jwt_template_custom_claims_present" in keys

    def test_clerk_jwt_template_long_lifetime_fires_for_extended(self):
        """Fires when lifetime_category='extended'."""
        keys = _rule_keys(evaluate(_jwt_template(lifetime_category="extended")))
        assert "clerk_jwt_template_long_lifetime" in keys

    def test_clerk_jwt_template_long_lifetime_fires_for_long(self):
        """Also fires for lifetime_category='long'."""
        keys = _rule_keys(evaluate(_jwt_template(lifetime_category="long")))
        assert "clerk_jwt_template_long_lifetime" in keys

    def test_both_jwt_template_rules_can_fire_together(self):
        keys = _rule_keys(evaluate(_jwt_template(
            custom_claims_present=True,
            lifetime_category="extended",
        )))
        assert "clerk_jwt_template_custom_claims_present" in keys
        assert "clerk_jwt_template_long_lifetime" in keys


class TestWebhookEndpointRulesTrigger:
    def test_clerk_webhook_endpoint_disabled_fires_when_enabled_false(self):
        """Fires when enabled=False."""
        keys = _rule_keys(evaluate(_webhook_endpoint(enabled=False)))
        assert "clerk_webhook_endpoint_disabled" in keys

    def test_clerk_webhook_without_signing_fires_when_url_present_no_secret(self):
        """Fires when url_present=True and secret_present=False."""
        keys = _rule_keys(evaluate(_webhook_endpoint(
            url_present=True,
            secret_present=False,
        )))
        assert "clerk_webhook_without_signing" in keys

    def test_clerk_webhook_non_https_fires_when_url_present_and_http(self):
        """Fires when url_present=True and url_scheme_category='http'."""
        keys = _rule_keys(evaluate(_webhook_endpoint(
            url_present=True,
            url_scheme_category="http",
        )))
        assert "clerk_webhook_non_https" in keys

    def test_all_webhook_rules_can_fire_together(self):
        keys = _rule_keys(evaluate(_webhook_endpoint(
            enabled=False,
            url_present=True,
            url_scheme_category="http",
            secret_present=False,
        )))
        assert "clerk_webhook_endpoint_disabled" in keys
        assert "clerk_webhook_without_signing" in keys
        assert "clerk_webhook_non_https" in keys


class TestEmailSmsSettingsRulesTrigger:
    def test_clerk_email_sms_custom_sender_present_fires_when_true(self):
        """Fires when custom_sender_present=True."""
        keys = _rule_keys(evaluate(_email_sms_settings(custom_sender_present=True)))
        assert "clerk_email_sms_custom_sender_present" in keys


class TestAuthStrategyRulesTrigger:
    def test_clerk_auth_strategy_mfa_not_required_fires_when_mfa_enabled_but_not_required(self):
        """Fires when mfa_enabled=True and mfa_required=False."""
        keys = _rule_keys(evaluate(_auth_strategy(
            mfa_enabled=True,
            mfa_required=False,
        )))
        assert "clerk_auth_strategy_mfa_not_required" in keys

    def test_clerk_auth_strategy_password_without_mfa_fires(self):
        """Fires when password_enabled=True and mfa_required=False."""
        keys = _rule_keys(evaluate(_auth_strategy(
            password_enabled=True,
            mfa_required=False,
        )))
        assert "clerk_auth_strategy_password_without_mfa" in keys

    def test_both_auth_strategy_rules_can_fire_together(self):
        keys = _rule_keys(evaluate(_auth_strategy(
            mfa_enabled=True,
            mfa_required=False,
            password_enabled=True,
        )))
        assert "clerk_auth_strategy_mfa_not_required" in keys
        assert "clerk_auth_strategy_password_without_mfa" in keys


class TestSessionPolicyRulesTrigger:
    def test_clerk_session_lifetime_extended_fires_for_extended(self):
        """Fires when session_lifetime_category='extended'."""
        keys = _rule_keys(evaluate(_session_policy(session_lifetime_category="extended")))
        assert "clerk_session_lifetime_extended" in keys

    def test_clerk_session_lifetime_extended_fires_for_very_long(self):
        """Also fires when session_lifetime_category='very_long'."""
        keys = _rule_keys(evaluate(_session_policy(session_lifetime_category="very_long")))
        assert "clerk_session_lifetime_extended" in keys

    def test_clerk_session_inactivity_timeout_extended_fires_when_extended(self):
        """Fires when inactivity_timeout_category='extended'."""
        keys = _rule_keys(evaluate(_session_policy(inactivity_timeout_category="extended")))
        assert "clerk_session_inactivity_timeout_extended" in keys

    def test_clerk_session_single_session_disabled_fires_when_false(self):
        """Fires when single_session_mode=False."""
        keys = _rule_keys(evaluate(_session_policy(single_session_mode=False)))
        assert "clerk_session_single_session_disabled" in keys

    def test_clerk_session_token_rotation_disabled_fires_when_false(self):
        """Fires when token_rotation_enabled=False."""
        keys = _rule_keys(evaluate(_session_policy(token_rotation_enabled=False)))
        assert "clerk_session_token_rotation_disabled" in keys

    def test_all_session_policy_rules_can_fire_together(self):
        keys = _rule_keys(evaluate(_session_policy(
            session_lifetime_category="extended",
            inactivity_timeout_category="extended",
            single_session_mode=False,
            token_rotation_enabled=False,
        )))
        assert "clerk_session_lifetime_extended" in keys
        assert "clerk_session_inactivity_timeout_extended" in keys
        assert "clerk_session_single_session_disabled" in keys
        assert "clerk_session_token_rotation_disabled" in keys


# ── Section C: Rule non-trigger tests (negative / healthy records) ─────────────


class TestInstanceSettingsRulesNotTrigger:
    def test_mfa_enabled_does_not_fire_instance_mfa_disabled(self):
        keys = _rule_keys(evaluate(_instance_settings(mfa_enabled=True)))
        assert "clerk_instance_mfa_disabled" not in keys

    def test_password_with_mfa_does_not_fire_password_without_mfa(self):
        keys = _rule_keys(evaluate(_instance_settings(
            password_enabled=True,
            mfa_enabled=True,
        )))
        assert "clerk_instance_password_without_mfa" not in keys

    def test_password_disabled_no_mfa_does_not_fire_password_without_mfa(self):
        """Rule only fires when BOTH password_enabled=True AND mfa_enabled=False."""
        keys = _rule_keys(evaluate(_instance_settings(
            password_enabled=False,
            mfa_enabled=False,
        )))
        assert "clerk_instance_password_without_mfa" not in keys

    def test_sign_up_disabled_does_not_fire_sign_up_enabled(self):
        keys = _rule_keys(evaluate(_instance_settings(sign_up_enabled=False)))
        assert "clerk_instance_sign_up_enabled" not in keys

    def test_healthy_instance_settings_produces_no_findings(self):
        findings = evaluate(_instance_settings(
            mfa_enabled=True,
            password_enabled=True,
            sign_up_enabled=False,
        ))
        instance_rules = {
            "clerk_instance_mfa_disabled",
            "clerk_instance_password_without_mfa",
            "clerk_instance_sign_up_enabled",
        }
        fired = {f.rule_key for f in findings} & instance_rules
        assert fired == set(), f"Unexpected instance rules fired: {fired}"


class TestApplicationRulesNotTrigger:
    def test_mfa_required_true_does_not_fire(self):
        keys = _rule_keys(evaluate(_application(mfa_required=True)))
        assert "clerk_application_mfa_not_required" not in keys

    def test_healthy_application_produces_no_findings(self):
        findings = evaluate(_application(mfa_required=True))
        assert findings == []


class TestDomainRulesNotTrigger:
    def test_verified_domain_does_not_fire_unverified(self):
        keys = _rule_keys(evaluate(_domain(verified=True)))
        assert "clerk_domain_unverified" not in keys

    def test_ssl_enabled_does_not_fire_ssl_disabled(self):
        keys = _rule_keys(evaluate(_domain(ssl_enabled=True)))
        assert "clerk_domain_ssl_disabled" not in keys

    def test_healthy_domain_produces_no_findings(self):
        findings = evaluate(_domain(verified=True, ssl_enabled=True))
        assert findings == []


class TestRedirectUrlRulesNotTrigger:
    def test_https_url_does_not_fire_non_https(self):
        keys = _rule_keys(evaluate(_redirect_url(
            url_present=True,
            url_scheme_category="https",
        )))
        assert "clerk_redirect_url_non_https" not in keys

    def test_no_url_does_not_fire_non_https(self):
        """url_present=False should not fire redirect_url_non_https."""
        keys = _rule_keys(evaluate(_redirect_url(
            url_present=False,
            url_scheme_category="http",
        )))
        assert "clerk_redirect_url_non_https" not in keys

    def test_no_wildcard_does_not_fire_wildcard_present(self):
        keys = _rule_keys(evaluate(_redirect_url(wildcard_present=False)))
        assert "clerk_redirect_url_wildcard_present" not in keys

    def test_no_localhost_does_not_fire_localhost_present(self):
        keys = _rule_keys(evaluate(_redirect_url(localhost_present=False)))
        assert "clerk_redirect_url_localhost_present" not in keys

    def test_healthy_redirect_url_produces_no_findings(self):
        findings = evaluate(_redirect_url(
            url_present=True,
            url_scheme_category="https",
            wildcard_present=False,
            localhost_present=False,
        ))
        assert findings == []


class TestJwtTemplateRulesNotTrigger:
    def test_no_custom_claims_does_not_fire_custom_claims_present(self):
        keys = _rule_keys(evaluate(_jwt_template(custom_claims_present=False)))
        assert "clerk_jwt_template_custom_claims_present" not in keys

    def test_standard_lifetime_does_not_fire_long_lifetime(self):
        for cat in ("short", "standard"):
            keys = _rule_keys(evaluate(_jwt_template(lifetime_category=cat)))
            assert "clerk_jwt_template_long_lifetime" not in keys, (
                f"fired for lifetime_category={cat!r}"
            )

    def test_healthy_jwt_template_produces_no_findings(self):
        findings = evaluate(_jwt_template(
            custom_claims_present=False,
            lifetime_category="standard",
        ))
        assert findings == []


class TestWebhookEndpointRulesNotTrigger:
    def test_enabled_webhook_does_not_fire_disabled(self):
        keys = _rule_keys(evaluate(_webhook_endpoint(enabled=True)))
        assert "clerk_webhook_endpoint_disabled" not in keys

    def test_webhook_with_secret_does_not_fire_without_signing(self):
        keys = _rule_keys(evaluate(_webhook_endpoint(
            url_present=True,
            secret_present=True,
        )))
        assert "clerk_webhook_without_signing" not in keys

    def test_webhook_no_url_does_not_fire_without_signing(self):
        """Without url_present=True, webhook_without_signing must not fire."""
        keys = _rule_keys(evaluate(_webhook_endpoint(
            url_present=False,
            secret_present=False,
        )))
        assert "clerk_webhook_without_signing" not in keys

    def test_https_webhook_does_not_fire_non_https(self):
        keys = _rule_keys(evaluate(_webhook_endpoint(
            url_present=True,
            url_scheme_category="https",
        )))
        assert "clerk_webhook_non_https" not in keys

    def test_healthy_webhook_produces_no_findings(self):
        findings = evaluate(_webhook_endpoint(
            enabled=True,
            url_present=True,
            url_scheme_category="https",
            secret_present=True,
        ))
        assert findings == []


class TestEmailSmsSettingsRulesNotTrigger:
    def test_no_custom_sender_does_not_fire(self):
        keys = _rule_keys(evaluate(_email_sms_settings(custom_sender_present=False)))
        assert "clerk_email_sms_custom_sender_present" not in keys

    def test_healthy_email_sms_settings_produces_no_findings(self):
        findings = evaluate(_email_sms_settings(custom_sender_present=False))
        assert findings == []


class TestAuthStrategyRulesNotTrigger:
    def test_mfa_not_enabled_does_not_fire_mfa_not_required(self):
        """Rule requires mfa_enabled=True — if MFA is not enabled it cannot be 'not required'."""
        keys = _rule_keys(evaluate(_auth_strategy(
            mfa_enabled=False,
            mfa_required=False,
        )))
        assert "clerk_auth_strategy_mfa_not_required" not in keys

    def test_mfa_required_true_does_not_fire_mfa_not_required(self):
        keys = _rule_keys(evaluate(_auth_strategy(
            mfa_enabled=True,
            mfa_required=True,
        )))
        assert "clerk_auth_strategy_mfa_not_required" not in keys

    def test_password_disabled_does_not_fire_password_without_mfa(self):
        keys = _rule_keys(evaluate(_auth_strategy(
            password_enabled=False,
            mfa_required=False,
        )))
        assert "clerk_auth_strategy_password_without_mfa" not in keys

    def test_password_with_required_mfa_does_not_fire_password_without_mfa(self):
        keys = _rule_keys(evaluate(_auth_strategy(
            password_enabled=True,
            mfa_required=True,
        )))
        assert "clerk_auth_strategy_password_without_mfa" not in keys

    def test_healthy_auth_strategy_produces_no_findings(self):
        findings = evaluate(_auth_strategy(
            mfa_enabled=True,
            mfa_required=True,
            password_enabled=True,
        ))
        assert findings == []


class TestSessionPolicyRulesNotTrigger:
    def test_standard_lifetime_does_not_fire_lifetime_extended(self):
        for cat in ("short", "standard"):
            keys = _rule_keys(evaluate(_session_policy(session_lifetime_category=cat)))
            assert "clerk_session_lifetime_extended" not in keys, (
                f"fired for session_lifetime_category={cat!r}"
            )

    def test_standard_inactivity_does_not_fire_inactivity_extended(self):
        for cat in ("none", "short", "standard"):
            keys = _rule_keys(evaluate(_session_policy(inactivity_timeout_category=cat)))
            assert "clerk_session_inactivity_timeout_extended" not in keys, (
                f"fired for inactivity_timeout_category={cat!r}"
            )

    def test_single_session_mode_true_does_not_fire_single_session_disabled(self):
        keys = _rule_keys(evaluate(_session_policy(single_session_mode=True)))
        assert "clerk_session_single_session_disabled" not in keys

    def test_token_rotation_enabled_does_not_fire_rotation_disabled(self):
        keys = _rule_keys(evaluate(_session_policy(token_rotation_enabled=True)))
        assert "clerk_session_token_rotation_disabled" not in keys

    def test_healthy_session_policy_produces_no_findings(self):
        findings = evaluate(_session_policy(
            session_lifetime_category="standard",
            inactivity_timeout_category="standard",
            single_session_mode=True,
            token_rotation_enabled=True,
        ))
        assert findings == []


# ── Section D: Evidence privacy scan ──────────────────────────────────────────


class TestEvidencePrivacy:

    def _all_triggering_findings(self) -> list:
        """Produce one finding from each record type by using triggering records."""
        records = [
            # Instance settings — all three instance rules
            _instance_settings(mfa_enabled=False, password_enabled=True, sign_up_enabled=True),
            # Application — mfa_not_required
            _application(mfa_required=False),
            # Domain — both domain rules
            _domain(verified=False, ssl_enabled=False),
            # Redirect URL — all three redirect rules
            _redirect_url(
                url_present=True,
                url_scheme_category="http",
                wildcard_present=True,
                localhost_present=True,
            ),
            # JWT template — both jwt rules
            _jwt_template(custom_claims_present=True, lifetime_category="extended"),
            # Webhook — all three webhook rules
            _webhook_endpoint(
                enabled=False,
                url_present=True,
                url_scheme_category="http",
                secret_present=False,
            ),
            # Email/SMS
            _email_sms_settings(custom_sender_present=True),
            # Auth strategy — both auth rules
            _auth_strategy(mfa_enabled=True, mfa_required=False, password_enabled=True),
            # Session policy — all four session rules
            _session_policy(
                session_lifetime_category="extended",
                inactivity_timeout_category="extended",
                single_session_mode=False,
                token_rotation_enabled=False,
            ),
        ]
        all_findings: list = []
        for rec in records:
            all_findings.extend(evaluate(rec))
        return all_findings

    def test_all_21_rules_produce_at_least_one_finding(self):
        findings = self._all_triggering_findings()
        found_keys = {f.rule_key for f in findings}
        missing = EXPECTED_RULE_KEYS - found_keys
        assert not missing, f"These rules produced no findings: {sorted(missing)}"

    def test_no_forbidden_fields_in_any_evidence(self):
        for finding in self._all_triggering_findings():
            for key in finding.evidence:
                assert key not in _FORBIDDEN_EVIDENCE_FIELDS, (
                    f"Forbidden evidence field {key!r} found for rule {finding.rule_key!r}"
                )

    def test_no_forbidden_strings_in_evidence_values(self):
        """Forbidden strings must not appear in evidence STRING VALUES (not key names).

        The 'rule' field contains the rule key string (e.g.,
        'clerk_redirect_url_localhost_present') which is a safe internal label,
        not a URL or credential. It is excluded from the substring scan.
        """
        for finding in self._all_triggering_findings():
            for field_key, val in finding.evidence.items():
                # Skip the 'rule' field — it holds the rule key string label, which
                # may legitimately contain substrings like 'localhost' as part of the
                # rule name (e.g., clerk_redirect_url_localhost_present).
                if field_key == "rule":
                    continue
                if not isinstance(val, str):
                    continue
                for forbidden in _FORBIDDEN_EVIDENCE_STRINGS:
                    assert forbidden.lower() not in val.lower(), (
                        f"Forbidden string {forbidden!r} in evidence string value "
                        f"{val!r} (field {field_key!r}) for rule {finding.rule_key!r}"
                    )

    def test_no_placeholder_secrets_in_evidence(self):
        for finding in self._all_triggering_findings():
            ev_str = str(finding.evidence)
            assert CLERK_TEST_SECRET_KEY not in ev_str
            assert CLERK_TEST_PUBLISHABLE_KEY not in ev_str

    def test_finding_key_format(self):
        """All findings must have a finding_key containing ':'."""
        for finding in self._all_triggering_findings():
            assert ":" in finding.finding_key, (
                f"finding_key {finding.finding_key!r} does not contain ':'"
            )

    def test_all_findings_have_provider_clerk(self):
        for finding in self._all_triggering_findings():
            assert finding.provider == "clerk", (
                f"Finding {finding.rule_key!r} has provider={finding.provider!r}"
            )

    def test_all_findings_have_valid_severity(self):
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for finding in self._all_triggering_findings():
            assert finding.severity in valid_severities, (
                f"Finding {finding.rule_key!r} has invalid severity {finding.severity!r}"
            )

    def test_all_findings_have_record_id(self):
        for finding in self._all_triggering_findings():
            assert finding.record_id is not None, (
                f"Finding {finding.rule_key!r} has no record_id"
            )

    def test_no_raw_domain_name_in_domain_evidence(self):
        findings = evaluate(_domain(verified=False, ssl_enabled=False))
        for f in findings:
            ev_str = str(f.evidence)
            # domain_type category label is safe; a raw domain string is not
            assert "example.com" not in ev_str
            assert "myapp" not in ev_str

    def test_no_raw_url_in_redirect_url_evidence(self):
        findings = evaluate(_redirect_url(
            url_present=True,
            url_scheme_category="http",
            wildcard_present=True,
            localhost_present=True,
        ))
        for f in findings:
            ev_str = str(f.evidence)
            assert "example.com" not in ev_str
            assert "myapp" not in ev_str

    def test_no_raw_url_in_webhook_evidence(self):
        findings = evaluate(_webhook_endpoint(
            url_present=True,
            url_scheme_category="http",
            secret_present=False,
        ))
        for f in findings:
            ev_str = str(f.evidence)
            assert "example.com" not in ev_str

    def test_no_jwt_payload_in_jwt_template_evidence(self):
        findings = evaluate(_jwt_template(
            custom_claims_present=True,
            lifetime_category="extended",
        ))
        for f in findings:
            ev_str = str(f.evidence)
            # claim keys, values, audience, and template body must never appear
            assert "eyJ" not in ev_str
            assert "audience" not in f.evidence
            assert "claims" not in f.evidence

    def test_no_email_address_in_email_sms_evidence(self):
        findings = evaluate(_email_sms_settings(custom_sender_present=True))
        for f in findings:
            assert "@" not in str(f.evidence)
            assert "email" not in f.evidence
            assert "phone" not in f.evidence

    def test_finding_keys_are_unique_within_record(self):
        """Each rule produces a unique finding_key per record."""
        findings = evaluate(_instance_settings(
            mfa_enabled=False,
            password_enabled=True,
            sign_up_enabled=True,
        ))
        keys = [f.finding_key for f in findings]
        assert len(keys) == len(set(keys)), f"Duplicate finding_keys: {keys}"

    def test_evidence_privacy_scan(self):
        """Comprehensive sweep: no forbidden field keys or forbidden string values in any evidence.

        Forbidden string substrings are checked against evidence STRING VALUES only
        (not field/key names) to avoid false positives from boolean field names like
        'localhost_present' or rule key strings like 'clerk_redirect_url_localhost_present'.
        The 'rule' field is excluded from substring checks because it holds the rule key
        label which may legitimately contain pattern-like substrings.
        """
        for finding in self._all_triggering_findings():
            # Check field keys
            for key in finding.evidence:
                assert key not in _FORBIDDEN_EVIDENCE_FIELDS, (
                    f"Rule {finding.rule_key!r}: forbidden evidence field {key!r}"
                )
            # Check string VALUES only (not key names); exclude 'rule' field
            for field_key, val in finding.evidence.items():
                if field_key == "rule":
                    continue
                if isinstance(val, str):
                    for forbidden in _FORBIDDEN_EVIDENCE_STRINGS:
                        assert forbidden.lower() not in val.lower(), (
                            f"Rule {finding.rule_key!r}: forbidden string {forbidden!r} "
                            f"in evidence field {field_key!r} value {val!r}"
                        )


# ── Section E: Registry / confidence / pack wiring ────────────────────────────


class TestRegistryWiring:
    def test_all_clerk_rules_in_registry(self):
        """Every key in CLERK_RULE_KEYS must be in KNOWN_RULE_KEYS."""
        for key in CLERK_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"Rule key {key!r} not in KNOWN_RULE_KEYS"

    def test_is_known_rule_key_returns_true_for_all_clerk_rules(self):
        for key in CLERK_RULE_KEYS:
            assert is_known_rule_key(key), f"is_known_rule_key({key!r}) returned False"

    def test_all_clerk_rules_have_confidence(self):
        """Every key in CLERK_RULE_KEYS must have an entry in RULE_CONFIDENCE."""
        for key in CLERK_RULE_KEYS:
            assert key in RULE_CONFIDENCE, (
                f"Rule key {key!r} missing from RULE_CONFIDENCE"
            )

    def test_all_clerk_confidence_levels_are_valid(self):
        from app.services.security_rule_confidence import HIGH, MEDIUM, LOW
        for key in CLERK_RULE_KEYS:
            conf_entry = RULE_CONFIDENCE.get(key)
            assert conf_entry is not None, f"No RULE_CONFIDENCE entry for {key!r}"
            conf, _ = conf_entry
            assert conf in (HIGH, MEDIUM, LOW), (
                f"Rule {key!r} has unexpected confidence level: {conf!r}"
            )

    def test_confidence_for_returns_value_for_all_clerk_rules(self):
        for key in CLERK_RULE_KEYS:
            result = confidence_for(key)
            assert result is not None, f"confidence_for({key!r}) returned None"

    def test_all_clerk_rules_in_pack(self):
        """Every key in CLERK_RULE_KEYS must have an entry in _RULE_META."""
        for key in CLERK_RULE_KEYS:
            assert key in _RULE_META, f"Rule key {key!r} missing from _RULE_META"

    def test_all_clerk_pack_entries_have_correct_provider(self):
        for key in CLERK_RULE_KEYS:
            provider, _, _ = _RULE_META[key]
            assert provider == "clerk", (
                f"Rule {key!r} has wrong provider in _RULE_META: {provider!r}"
            )

    def test_all_clerk_pack_entries_have_valid_severity(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for key in CLERK_RULE_KEYS:
            _, severity, _ = _RULE_META[key]
            assert severity in valid, (
                f"Rule {key!r} has invalid severity in _RULE_META: {severity!r}"
            )

    def test_pack_summary_includes_clerk_rules(self):
        rules = list_pack_rules()
        clerk_keys = {r["rule_key"] for r in rules if r["provider"] == "clerk"}
        assert CLERK_RULE_KEYS <= clerk_keys, (
            f"Missing from list_pack_rules: {CLERK_RULE_KEYS - clerk_keys}"
        )


# ── Section F: Coverage service ───────────────────────────────────────────────


class TestCoverageService:
    def test_clerk_in_providers(self):
        """'clerk' must be in PROVIDERS."""
        assert "clerk" in PROVIDERS

    def test_all_clerk_rules_in_rule_record_types(self):
        """Every key in CLERK_RULE_KEYS must be in RULE_RECORD_TYPES."""
        for key in CLERK_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, (
                f"Rule key {key!r} missing from RULE_RECORD_TYPES"
            )

    def test_clerk_surfaces(self):
        """'clerk' must be in PROVIDER_SURFACES."""
        assert "clerk" in PROVIDER_SURFACES

    def test_clerk_surfaces_non_empty(self):
        assert len(PROVIDER_SURFACES["clerk"]) >= 1

    def test_m83a_record_types_in_rule_record_types(self):
        """All 10 clerk record type strings must appear as values in RULE_RECORD_TYPES."""
        all_record_types_in_map: set[str] = set()
        for rtype_tuple in RULE_RECORD_TYPES.values():
            for rt in rtype_tuple:
                all_record_types_in_map.add(rt)

        expected_clerk_record_types = {
            CLERK_INSTANCE_SETTINGS,
            CLERK_APPLICATION,
            CLERK_DOMAIN,
            CLERK_REDIRECT_URL_CONFIG,
            CLERK_JWT_TEMPLATE,
            CLERK_WEBHOOK_ENDPOINT,
            CLERK_EMAIL_SMS_SETTINGS,
            CLERK_AUTH_STRATEGY,
            CLERK_ORGANIZATION_SETTINGS,
            CLERK_SESSION_POLICY,
        }
        # All clerk record types that are mapped to at least one rule
        clerk_rt_in_map = all_record_types_in_map & expected_clerk_record_types
        # The 9 record types that have rules defined must be present;
        # clerk_organization_settings has no rules in M83B but we still
        # check that at least the 9 covered ones are wired.
        expected_covered = {
            CLERK_INSTANCE_SETTINGS,
            CLERK_APPLICATION,
            CLERK_DOMAIN,
            CLERK_REDIRECT_URL_CONFIG,
            CLERK_JWT_TEMPLATE,
            CLERK_WEBHOOK_ENDPOINT,
            CLERK_EMAIL_SMS_SETTINGS,
            CLERK_AUTH_STRATEGY,
            CLERK_SESSION_POLICY,
        }
        missing = expected_covered - clerk_rt_in_map
        assert not missing, (
            f"These Clerk record types are not mapped in RULE_RECORD_TYPES: {sorted(missing)}"
        )

    def test_rule_record_types_map_to_clerk_record_types(self):
        """All RULE_RECORD_TYPES entries for Clerk rules must reference Clerk record types."""
        from app.connectors.clerk_schema import CLERK_RECORD_TYPES
        for key in CLERK_RULE_KEYS:
            for rtype in RULE_RECORD_TYPES[key]:
                assert rtype in CLERK_RECORD_TYPES, (
                    f"Rule {key!r} maps to unexpected record type {rtype!r}"
                )


# ── Section G: Capability matrix + expansion framework ────────────────────────


class TestCapabilityMatrix:

    def _clerk_cap(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("clerk")
        assert cap is not None, "Clerk must have a capability matrix entry"
        return cap

    def test_capability_matrix_clerk_security_rules_true(self):
        cap = self._clerk_cap()
        assert cap.security.security_rules is True, (
            "After M83B, clerk capability matrix security_rules must be True"
        )

    def test_capability_matrix_clerk_drift_risk_classification_true(self):
        cap = self._clerk_cap()
        assert cap.drift.drift_risk_classification is True

    def test_capability_matrix_clerk_activity_ingestion_false(self):
        # M83D promoted activity_ingestion to True; update assertion to reflect current state.
        cap = self._clerk_cap()
        assert cap.security.activity_ingestion is True, (
            "M83D adds activity ingestion — activity_ingestion must be True after M83D"
        )

    def test_capability_matrix_clerk_has_entry(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES, PROVIDER_CAPABILITIES_PARTIAL,
        )
        all_providers = [p.provider for p in PROVIDER_CAPABILITIES + PROVIDER_CAPABILITIES_PARTIAL]
        assert "clerk" in all_providers

    def test_expansion_framework_m83c(self):
        """After M83B, planned_next_stage should reference M83C or a later Clerk stage."""
        framework = get_framework()
        stage = framework["summary"]["planned_next_stage"]
        assert (
            "M83C" in stage or "M83D" in stage or "M83E" in stage
            or "M83F" in stage or "M83G" in stage or "M83H" in stage
            or "M83I" in stage or "M84A" in stage or "PagerDuty" in stage
            or "M85A" in stage or "Linear" in stage
            or "M86A" in stage or "Jira" in stage
        ), (
            f"After M83B, planned_next_stage should reference a post-M83B stage; got {stage!r}"
        )
        assert ("Clerk" in stage or "clerk" in stage.lower() or "PagerDuty" in stage or "M84" in stage
                or "M85A" in stage or "Linear" in stage or "M86A" in stage or "Jira" in stage), (
            f"planned_next_stage should mention Clerk, PagerDuty, Linear, or Jira arc; got {stage!r}"
        )

    def test_expansion_framework_exact_m83c_label(self):
        framework = get_framework()
        stage = framework["summary"]["planned_next_stage"]
        # M83C through M83I are complete; framework now points at M84A or later.
        assert stage in (
            "M83C: Clerk Auth/Application Risk Expansion",
            "M83D: Clerk Activity/Event Ingestion",
            "M83E: Clerk Activity Signals",
            "M83F: Clerk Risk × Activity Correlations",
            "M83G: Clerk Demo + QA",
            "M83H: Clerk Provider Depth QA",
            "M83I: Clerk Cross-Cloud UX Polish",
            "M84A: PagerDuty Drift Provider Foundation",
            "M84B: PagerDuty Core Security Foundation",
            "M84C: PagerDuty Escalation/Webhook Risk Expansion",
            "M84D: PagerDuty Activity/Event Ingestion",
            "M84E: PagerDuty Activity Signals",
            "M84F: PagerDuty Risk × Activity Correlations",
            "M84G: PagerDuty Demo + QA",
            "M84H: PagerDuty Provider Depth QA",
            "M84I: PagerDuty Cross-Cloud UX Polish",
            "M85A: Linear Drift Provider Foundation",
            "M85B: Linear Core Security Foundation",
            "M85C: Linear Workflow/Webhook Risk Expansion",
            "M85D: Linear Activity/Event Ingestion",
            "M85E: Linear Activity Signals",
            "M85F: Linear Risk × Activity Correlations",
            "M85G: Linear Demo + QA",
            "M85H: Linear Provider Depth QA",
            "M85I: Linear Cross-Cloud UX Polish",
            "M86A: Jira Drift Provider Foundation",
            "M86B: Jira Core Security Foundation",
            "M86C: Jira Workflow/Webhook Risk Expansion",
            "M86D: Jira Activity/Event Ingestion",
            "M86E: Jira Activity Signals",
            "M86F: Jira Risk × Activity Correlations",
            "M86G: Jira Demo + QA",
            "M86H: Jira Provider Depth QA",
            "M86I: Jira Cross-Cloud UX Polish",
            "M87A: GitLab Drift Provider Foundation",
        ), (
            f"Unexpected planned_next_stage value: {stage!r}"
        )

    def test_expansion_framework_clerk_not_in_recommended_queue(self):
        framework = get_framework()
        providers = [r["provider"] for r in framework.get("recommended_next_providers", [])]
        assert "clerk" not in providers, (
            "Clerk launched in M83A/B; must not remain in RECOMMENDED_NEXT_PROVIDERS"
        )

    def test_expansion_framework_not_pointing_to_m83b(self):
        """planned_next_stage must not still point at M83B (current milestone)."""
        framework = get_framework()
        stage = framework["summary"]["planned_next_stage"]
        assert "M83B" not in stage, (
            f"planned_next_stage still points at M83B (current milestone): {stage!r}"
        )


# ── Section H: Frontend catalog ───────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"


class TestFrontendCatalog:

    def _catalog_content(self) -> str:
        if not FE_CATALOG.exists():
            pytest.skip("securityRuleCatalog.ts not found")
        return FE_CATALOG.read_text()

    def test_frontend_catalog_has_clerk_rules(self):
        """All 21 clerk rule keys must appear in securityRuleCatalog.ts."""
        content = self._catalog_content()
        missing = []
        for key in EXPECTED_RULE_KEYS:
            if f'key: "{key}"' not in content:
                missing.append(key)
        assert not missing, (
            f"These Clerk rule keys are missing from securityRuleCatalog.ts: {sorted(missing)}"
        )

    def test_catalog_has_clerk_provider_entry(self):
        content = self._catalog_content()
        assert 'provider: "clerk"' in content

    def test_all_clerk_rule_keys_in_catalog_individually(self):
        content = self._catalog_content()
        for key in CLERK_RULE_KEYS:
            assert f'key: "{key}"' in content, (
                f"Rule key {key!r} not found in securityRuleCatalog.ts"
            )

    def test_no_forbidden_phrases_in_clerk_catalog_entries(self):
        content = self._catalog_content()
        start = content.find('key: "clerk_instance_mfa_disabled"')
        if start < 0:
            pytest.skip("Clerk section not found in catalog")
        clerk_section = content[start:]
        forbidden_phrases = [
            "compromise confirmed", "secret leaked", "data leaked",
            "customer data leaked", "payment fraud detected", "attacker found",
            "someone has access", "unauthorized access confirmed",
            "breach detected", "attack detected", "orders exposed",
            "card data exposed",
        ]
        for phrase in forbidden_phrases:
            assert phrase not in clerk_section.lower(), (
                f"Forbidden phrase {phrase!r} in Clerk catalog entries"
            )


# ── Section I: Forbidden wording scan ─────────────────────────────────────────

FORBIDDEN_CLAIM_PHRASES = [
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "customer data leaked",
    "payment fraud detected",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
]

_BE_ROOT = Path(__file__).resolve().parents[1]
_FE_SRC = REPO_ROOT / "frontend" / "src"


_CLERK_SOURCE_MODULES = [
    "app/services/security_rules/clerk.py",
    "app/connectors/clerk.py",
    "app/connectors/clerk_schema.py",
    "app/services/provider_capability_matrix_service.py",
    "app/services/integration_service.py",
    "app/workers/sync_task.py",
    "app/services/security_rule_registry.py",
    "app/services/security_rule_confidence.py",
    "app/services/security_rule_pack.py",
    "app/services/security_coverage_service.py",
    "app/services/security_finding_evaluator.py",
]


class TestForbiddenWording:

    def test_no_forbidden_wording(self):
        """Scan Clerk source modules and frontend/src for forbidden claim wording.

        Scoped to Clerk-related backend modules (not the full backend tree, which
        contains legitimate occurrences of these phrases in definition lists, test
        fixtures, negation contexts, and other provider incident-signal files).
        """
        violations: list[str] = []

        # Scan Clerk-related backend modules
        for module_path in _CLERK_SOURCE_MODULES:
            full_path = _BE_ROOT / module_path
            if not full_path.exists():
                continue
            content = full_path.read_text(encoding="utf-8", errors="replace")
            content_lower = content.lower()
            for phrase in FORBIDDEN_CLAIM_PHRASES:
                if phrase in content_lower:
                    # Check that the occurrence is not in a definition list
                    # (lines that define the forbidden phrases themselves are OK)
                    for line in content.split("\n"):
                        if phrase in line.lower():
                            line_stripped = line.strip()
                            # Skip lines that are defining/listing the phrase (string literal)
                            is_definition = (
                                line_stripped.startswith('"') or
                                line_stripped.startswith("'") or
                                line_stripped.startswith("#") or
                                "FORBIDDEN_CLAIM_PHRASES" in line or
                                "forbidden_claim_phrase" in line.lower()
                            )
                            if not is_definition:
                                violations.append(
                                    f"{module_path}: {phrase!r} in line: {line_stripped[:80]!r}"
                                )

        # Scan frontend (exclude demo/definition scripts that legitimately list
        # the forbidden phrases as "avoid" examples or forbidden-phrases registries)
        _FE_EXCLUDED = {"securityDemoScript.ts", "securityRuleCatalog.ts"}
        if _FE_SRC.exists():
            for ext in ("*.ts", "*.tsx"):
                for path in _FE_SRC.rglob(ext):
                    if path.name in _FE_EXCLUDED:
                        continue
                    content = path.read_text(encoding="utf-8", errors="replace").lower()
                    for phrase in FORBIDDEN_CLAIM_PHRASES:
                        if phrase in content:
                            violations.append(
                                f"{path.relative_to(REPO_ROOT)}: {phrase!r}"
                            )

        assert not violations, (
            f"Forbidden claim wording found in source files:\n" +
            "\n".join(f"  {v}" for v in violations[:20])
        )


# ── Section J: Secret-shape grep ──────────────────────────────────────────────

SECRET_PATTERNS = [
    r"eyJ[A-Za-z0-9_-]{10,}",                         # JWT
    r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",   # SendGrid key
    r"AC[0-9a-fA-F]{32}",                              # Twilio SID
    r"SK[0-9a-fA-F]{32}",                              # Twilio key
]


class TestSecretShapeGrep:

    def test_no_secret_shaped_strings(self):
        """Scan Clerk source modules and frontend/src for secret-pattern strings.

        Scoped to Clerk-related backend modules (same as M82B/M83A pattern).
        Test files are excluded to avoid flagging safe placeholder constants.
        """
        violations: list[str] = []

        # Scan Clerk-related backend modules (no test files)
        for module_path in _CLERK_SOURCE_MODULES:
            full_path = _BE_ROOT / module_path
            if not full_path.exists():
                continue
            if "test" in full_path.name.lower():
                continue
            content = full_path.read_text(encoding="utf-8", errors="replace")
            for pattern in SECRET_PATTERNS:
                match = re.search(pattern, content)
                if match:
                    violations.append(
                        f"{module_path}: pattern {pattern!r} matched {match.group()[:30]!r}"
                    )

        # Scan frontend/src
        if _FE_SRC.exists():
            for ext in ("*.ts", "*.tsx"):
                for path in _FE_SRC.rglob(ext):
                    content = path.read_text(encoding="utf-8", errors="replace")
                    for pattern in SECRET_PATTERNS:
                        match = re.search(pattern, content)
                        if match:
                            violations.append(
                                f"{path.relative_to(REPO_ROOT)}: "
                                f"pattern {pattern!r} matched {match.group()[:30]!r}"
                            )

        assert not violations, (
            f"Secret-shaped strings found in source files:\n" +
            "\n".join(f"  {v}" for v in violations[:20])
        )

    def test_placeholder_values_used_in_tests_are_safe(self):
        """The safe placeholder constants must not match secret patterns."""
        for pattern in SECRET_PATTERNS:
            assert re.search(pattern, CLERK_TEST_SECRET_KEY) is None, (
                f"CLERK_TEST_SECRET_KEY matches secret pattern {pattern!r}"
            )
            assert re.search(pattern, CLERK_TEST_PUBLISHABLE_KEY) is None, (
                f"CLERK_TEST_PUBLISHABLE_KEY matches secret pattern {pattern!r}"
            )
            assert re.search(pattern, CLERK_TEST_INSTANCE_ID) is None, (
                f"CLERK_TEST_INSTANCE_ID matches secret pattern {pattern!r}"
            )

    def test_no_real_clerk_key_shapes_in_test_file(self):
        """This test file must not contain real Clerk sk_live_ or pk_live_ key shapes."""
        src = Path(__file__).read_text()
        assert "CLERK_TEST_SECRET_KEY_PLACEHOLDER" in src, "Must use safe placeholders"
        assert not re.search(r"sk_live_[A-Za-z0-9]{20,}", src), (
            "Real Clerk sk_live_ key shape found in test file — use CLERK_TEST_SECRET_KEY_PLACEHOLDER"
        )
        assert not re.search(r"pk_live_[A-Za-z0-9]{20,}", src), (
            "Real Clerk pk_live_ key shape found in test file — use CLERK_TEST_PUBLISHABLE_KEY_PLACEHOLDER"
        )

    def test_no_jwt_in_test_file(self):
        src = Path(__file__).read_text()
        assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", src), (
            "JWT-shaped token found in this test file — use safe placeholders only"
        )


# ── Section: M83A regression ──────────────────────────────────────────────────


class TestM83ARegression:
    def test_m83a_clerk_record_types_still_importable(self):
        from app.connectors.clerk_schema import CLERK_RECORD_TYPES
        assert len(CLERK_RECORD_TYPES) == 10

    def test_clerk_connector_still_has_validate_and_fetch(self):
        from app.connectors.clerk import ClerkConnector
        conn = ClerkConnector()
        assert hasattr(conn, "validate_credentials")
        assert hasattr(conn, "fetch")

    def test_evaluator_dispatches_clerk(self):
        """'clerk' must be in _PROVIDER_RULES."""
        assert "clerk" in _PROVIDER_RULES

    def test_evaluator_dispatches_to_clerk_rules(self):
        """The clerk entry in _PROVIDER_RULES must be a non-empty list of callables."""
        rules = _PROVIDER_RULES["clerk"]
        assert len(rules) >= 1
        for rule_fn in rules:
            assert callable(rule_fn)

    def test_evaluate_record_dispatches_clerk_instance(self):
        """evaluate_record with a triggering clerk record must return findings."""
        rec = _instance_settings(mfa_enabled=False)
        findings = evaluate_record(rec, "clerk")
        keys = {f.rule_key for f in findings}
        assert "clerk_instance_mfa_disabled" in keys

    def test_datadog_regression_still_wired(self):
        """Regression: datadog must still be in _PROVIDER_RULES after M83B."""
        assert "datadog" in _PROVIDER_RULES

    def test_github_regression_still_wired(self):
        """Regression: github must still be in _PROVIDER_RULES after M83B."""
        assert "github" in _PROVIDER_RULES


# ── Section: Finding structure tests ──────────────────────────────────────────


class TestFindingStructure:

    def test_finding_key_prefixed_by_rule_key(self):
        """finding_key must start with rule_key (separated by ':')."""
        findings = evaluate(_instance_settings(mfa_enabled=False))
        for f in findings:
            assert f.finding_key.startswith(f.rule_key), (
                f"finding_key {f.finding_key!r} does not start with rule_key {f.rule_key!r}"
            )

    def test_all_record_types_return_list(self):
        """evaluate() must always return a list, never raise."""
        test_records = [
            _instance_settings(),
            _application(),
            _domain(),
            _redirect_url(),
            _jwt_template(),
            _webhook_endpoint(),
            _email_sms_settings(),
            _auth_strategy(),
            _organization_settings(),
            _session_policy(),
        ]
        for rec in test_records:
            result = evaluate(rec)
            assert isinstance(result, list), (
                f"evaluate returned {type(result)} for record_type={rec['record_type']!r}"
            )

    def test_malformed_record_does_not_raise(self):
        """Malformed records must never cause evaluate() to raise."""
        malformed_records: list[Any] = [
            {},
            {"record_type": CLERK_INSTANCE_SETTINGS},
            {"record_type": CLERK_INSTANCE_SETTINGS, "mfa_enabled": "not-a-bool"},
            {"record_type": CLERK_APPLICATION, "mfa_required": "not-a-bool"},
            {"record_type": CLERK_DOMAIN},
            {"record_type": CLERK_REDIRECT_URL_CONFIG},
            {"record_type": CLERK_JWT_TEMPLATE},
            {"record_type": CLERK_WEBHOOK_ENDPOINT},
            {"record_type": CLERK_EMAIL_SMS_SETTINGS},
            {"record_type": CLERK_AUTH_STRATEGY},
            {"record_type": CLERK_SESSION_POLICY},
        ]
        for rec in malformed_records:
            try:
                result = evaluate(rec)
                assert isinstance(result, list)
            except Exception as exc:
                pytest.fail(
                    f"evaluate raised on malformed record {rec!r}: {exc}"
                )

    def test_organization_settings_record_returns_empty_list(self):
        """clerk_organization_settings has no rules defined in M83B — must return []."""
        result = evaluate(_organization_settings())
        assert result == []
